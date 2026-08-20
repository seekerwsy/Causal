"""The sole outcome-bearing API for SecAware formal randomized confirmation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum

from pydantic import BaseModel, ValidationError

from secaware.analysis.confirmatory_contributions_v2 import (
    ConfirmatoryContributionArtifactV2,
    _derive_from_formal_context_v2,
)
from secaware.analysis.multi_support_simultaneous_v2 import (
    MultiSupportSimultaneousInferenceResultV2,
    MultiSupportSimultaneousIntervalV2,
    _run_frozen_domain_from_formal_context_v2,
)
from secaware.experiments.execution_v2 import ProvenanceClosedAssignmentCoverageManifestV2
from secaware.experiments.run_evidence_v2 import ConfirmatoryRunEvidenceManifestV2
from secaware.schema.common import model_shape_is_intact
from secaware.schema.experiment_freeze_v2 import ConfirmatoryExperimentFreezeV2
from secaware.schema.formal_analysis_v2 import (
    _FORMAL_CONTEXT_PROTOCOL_ACCESS,
    FormalAnalysisProtocolV2,
    FormalConfirmationStatusV2,
    FormalCoordinateLabelV2,
    FormalJointInterpretationV2,
    FormalNonEvaluableReasonV2,
)
from secaware.schema.inference_v2 import SimultaneousTestCoordinateV2
from secaware.schema.multi_support_inference_v2 import (
    _FORMAL_CONTEXT_PLAN_ACCESS,
    MultiSupportFormalFamilyV2,
    MultiSupportSimultaneousInferencePlanV2,
)
from secaware.schema.policy_v2 import ExpectedDirection
from secaware.schema.population_v2 import PopulationFreezeManifestV2

_FATAL = (MemoryError, KeyboardInterrupt, SystemExit)
_RESULT_PREFIX = "formal_confirmation_result_v2_"
_FORMAL_CONTEXT_SEAL = object()
_FORMAL_ENTRY_CONTEXT_ACCESS = object()


@dataclass(frozen=True, slots=True)
class FormalFamilyInferenceResultV2:
    formal_family: MultiSupportFormalFamilyV2
    inference_plan_id: str
    family_id: str
    contribution_artifact_ids: tuple[str, ...]
    contribution_artifacts: tuple[ConfirmatoryContributionArtifactV2, ...]
    simultaneous_result: MultiSupportSimultaneousInferenceResultV2


@dataclass(frozen=True, slots=True)
class FormalCoordinateDecisionV2:
    hypothesis_model_coordinate_id: str
    hypothesis_id: str
    model_id: str
    expected_direction: ExpectedDirection
    label: FormalCoordinateLabelV2
    primary_confirmed: bool
    target_vs_placebo_confirmed: bool
    target_vs_generic_confirmed: bool
    target_specificity_confirmed: bool
    joint_interpretation: FormalJointInterpretationV2
    primary_test_coordinate_id: str
    joint_test_coordinate_id: str
    placebo_test_coordinate_id: str
    generic_test_coordinate_id: str
    label_basis: str


@dataclass(frozen=True, slots=True)
class FormalConfirmationResultV2:
    formal_confirmation_result_id: str
    confirmatory_experiment_freeze_id: str
    confirmatory_run_evidence_manifest_id: str
    formal_analysis_protocol_id: str
    status: FormalConfirmationStatusV2
    non_evaluable_reason: FormalNonEvaluableReasonV2 | None
    failed_family: MultiSupportFormalFamilyV2 | None
    expected_assignment_count: int
    outcome_count: int
    terminal_failure_count: int
    terminal_failure_stage_counts: tuple[tuple[str, int], ...]
    family_results: tuple[FormalFamilyInferenceResultV2, ...]
    coordinate_decisions: tuple[FormalCoordinateDecisionV2, ...]
    complete_hypothesis_model_family_preserved: bool
    assigned_arm_itt_only: bool
    target_changed_and_semantic_validity_diagnostic_only: bool
    joint_outcome_can_promote_security_label: bool
    optional_jci_rfci_marker_per_protocol_present: bool
    optional_evidence_can_promote_confirmatory_label: bool
    confirmation_label_rule: str


@dataclass(frozen=True, slots=True)
class _FormalPlanBindingV2:
    formal_family: MultiSupportFormalFamilyV2
    plan: MultiSupportSimultaneousInferencePlanV2


@dataclass(frozen=True, slots=True)
class _FormalContributionInputBindingV2:
    formal_family: MultiSupportFormalFamilyV2
    hypothesis_id: str
    model_id: str
    population: PopulationFreezeManifestV2
    coverage: ProvenanceClosedAssignmentCoverageManifestV2
    coordinate: SimultaneousTestCoordinateV2


@dataclass(frozen=True, slots=True)
class _FormalArtifactBindingV2:
    formal_family: MultiSupportFormalFamilyV2
    hypothesis_id: str
    model_id: str
    artifact: ConfirmatoryContributionArtifactV2


def _error(message: str = "formal confirmation v2 failed validation") -> ValueError:
    return ValueError(message)


def _jsonable(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if is_dataclass(value) and not isinstance(value, type):
        return _jsonable(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            _jsonable(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _checked_experiment(
    experiment: ConfirmatoryExperimentFreezeV2,
) -> ConfirmatoryExperimentFreezeV2:
    if type(experiment) is not ConfirmatoryExperimentFreezeV2 or not model_shape_is_intact(
        experiment
    ):
        raise _error("exact confirmatory experiment freeze is required")
    try:
        return ConfirmatoryExperimentFreezeV2.model_validate(
            experiment.model_dump(mode="python", round_trip=True, warnings=False),
            strict=True,
        )
    except _FATAL:
        raise
    except (TypeError, ValueError, ValidationError):
        raise _error("confirmatory experiment freeze failed validation") from None


def _checked_run_evidence(
    run_evidence: ConfirmatoryRunEvidenceManifestV2,
) -> ConfirmatoryRunEvidenceManifestV2:
    if type(run_evidence) is not ConfirmatoryRunEvidenceManifestV2 or not model_shape_is_intact(
        run_evidence
    ):
        raise _error("exact confirmatory run evidence is required")
    try:
        return ConfirmatoryRunEvidenceManifestV2.model_validate(
            run_evidence.model_dump(mode="python", round_trip=True, warnings=False),
            strict=True,
        )
    except _FATAL:
        raise
    except (TypeError, ValueError, ValidationError):
        raise _error("confirmatory run evidence failed validation") from None


@dataclass(frozen=True, slots=True, init=False)
class _ValidatedFormalContextV2:
    """Sealed, immutable registry derived from the two fully checked roots.

    This is an internal API capability rather than a security sandbox.  Its
    constructor is disabled; the formal entry creates it only after both root
    round-trips and their exact cross-binding succeed.  Downstream fast paths
    receive this context plus a family/key, never caller-supplied plans,
    coverage, coordinates, or contribution artifacts.
    """

    _seal: object
    _phase: str
    _confirmatory_experiment_freeze_id: str
    _confirmatory_run_evidence_manifest_id: str
    _experiment: ConfirmatoryExperimentFreezeV2
    _evidence: ConfirmatoryRunEvidenceManifestV2
    _protocol: FormalAnalysisProtocolV2 | None
    _plan_bindings: tuple[_FormalPlanBindingV2, ...]
    _input_bindings: tuple[_FormalContributionInputBindingV2, ...]
    _artifact_bindings: tuple[_FormalArtifactBindingV2, ...]
    _registry_sha256: str

    @classmethod
    def _from_roots(
        cls,
        experiment_freeze: ConfirmatoryExperimentFreezeV2,
        run_evidence: ConfirmatoryRunEvidenceManifestV2,
        *,
        access: object,
    ) -> _ValidatedFormalContextV2:
        if access is not _FORMAL_ENTRY_CONTEXT_ACCESS:
            raise _error("formal context can only be created by the formal entry")
        experiment = _checked_experiment(experiment_freeze)
        evidence = _checked_run_evidence(run_evidence)
        if evidence.experiment_freeze != experiment:
            raise _error("run evidence does not belong to the exact experiment freeze")

        context = object.__new__(cls)
        object.__setattr__(context, "_seal", _FORMAL_CONTEXT_SEAL)
        object.__setattr__(context, "_phase", "roots")
        object.__setattr__(
            context,
            "_confirmatory_experiment_freeze_id",
            experiment.confirmatory_experiment_freeze_id,
        )
        object.__setattr__(
            context,
            "_confirmatory_run_evidence_manifest_id",
            evidence.confirmatory_run_evidence_manifest_id,
        )
        object.__setattr__(context, "_experiment", experiment)
        object.__setattr__(context, "_evidence", evidence)
        object.__setattr__(context, "_protocol", None)
        object.__setattr__(context, "_plan_bindings", ())
        object.__setattr__(context, "_input_bindings", ())
        object.__setattr__(context, "_artifact_bindings", ())
        object.__setattr__(context, "_registry_sha256", "")

        protocol = FormalAnalysisProtocolV2._from_formal_context(context)
        plans = tuple(
            _FormalPlanBindingV2(formal_family=plan.formal_family, plan=plan)
            for plan in protocol.family_plans
        )
        if tuple(item.formal_family for item in plans) != tuple(MultiSupportFormalFamilyV2):
            raise _error("formal context plan registry is incomplete")
        object.__setattr__(context, "_protocol", protocol)
        object.__setattr__(context, "_plan_bindings", plans)

        if evidence.formal_point_estimation_ready:
            inputs = context._derive_input_bindings()
            object.__setattr__(context, "_input_bindings", inputs)
            object.__setattr__(context, "_phase", "inputs")
            artifacts = tuple(
                _FormalArtifactBindingV2(
                    formal_family=binding.formal_family,
                    hypothesis_id=binding.hypothesis_id,
                    model_id=binding.model_id,
                    artifact=_derive_from_formal_context_v2(
                        context,
                        formal_family=binding.formal_family,
                        hypothesis_id=binding.hypothesis_id,
                        model_id=binding.model_id,
                    ),
                )
                for binding in inputs
            )
            object.__setattr__(context, "_artifact_bindings", artifacts)

        object.__setattr__(context, "_phase", "complete")
        object.__setattr__(context, "_registry_sha256", context._registry_digest())
        context._assert_complete_registry()
        return context

    def _assert_roots(self) -> None:
        try:
            if (
                type(self) is not _ValidatedFormalContextV2
                or self._seal is not _FORMAL_CONTEXT_SEAL
                or self._phase not in {"roots", "inputs", "complete"}
                or type(self._experiment) is not ConfirmatoryExperimentFreezeV2
                or not model_shape_is_intact(self._experiment)
                or type(self._evidence) is not ConfirmatoryRunEvidenceManifestV2
                or not model_shape_is_intact(self._evidence)
                or self._experiment.confirmatory_experiment_freeze_id
                != self._confirmatory_experiment_freeze_id
                or self._evidence.confirmatory_run_evidence_manifest_id
                != self._confirmatory_run_evidence_manifest_id
                or self._evidence.experiment_freeze != self._experiment
            ):
                raise _error("sealed formal context failed root validation")
        except _FATAL:
            raise
        except ValueError:
            raise
        except Exception:  # noqa: BLE001 - normalize forged/uninitialized instances
            raise _error("sealed formal context failed root validation") from None

    def _experiment_for_protocol_builder(self, access: object) -> ConfirmatoryExperimentFreezeV2:
        if access is not _FORMAL_CONTEXT_PROTOCOL_ACCESS:
            raise _error("formal protocol builder requires the sealed context")
        self._assert_roots()
        return self._experiment

    def _experiment_for_plan_builder(self, access: object) -> ConfirmatoryExperimentFreezeV2:
        if access is not _FORMAL_CONTEXT_PLAN_ACCESS:
            raise _error("formal plan builder requires the sealed context")
        self._assert_roots()
        return self._experiment

    @property
    def experiment(self) -> ConfirmatoryExperimentFreezeV2:
        self._assert_roots()
        if self._phase != "complete":
            raise _error("formal context is not complete")
        return self._experiment

    @property
    def evidence(self) -> ConfirmatoryRunEvidenceManifestV2:
        self._assert_roots()
        if self._phase != "complete":
            raise _error("formal context is not complete")
        return self._evidence

    @property
    def protocol(self) -> FormalAnalysisProtocolV2:
        self._assert_roots()
        if self._phase != "complete" or self._protocol is None:
            raise _error("formal context is not complete")
        return self._protocol

    def _derive_input_bindings(self) -> tuple[_FormalContributionInputBindingV2, ...]:
        self._assert_roots()
        if self._protocol is None:
            raise _error("formal context protocol is unavailable")
        accounting_by_hypothesis = {
            item.execution_policy_freeze.randomization.population.hypothesis.hypothesis_id: item
            for item in self._evidence.total_assignment_accountings
        }
        population_by_hypothesis = {
            item.intervention_bridge.frozen_hypothesis.hypothesis_id: item.population
            for item in self._experiment.protocol_roots
        }
        bindings = []
        for plan in self._protocol.family_plans:
            for coordinate in plan.family.coordinates:
                accounting = accounting_by_hypothesis.get(coordinate.hypothesis_id)
                population = population_by_hypothesis.get(coordinate.hypothesis_id)
                if (
                    accounting is None
                    or population is None
                    or accounting.confirmatory_coverage is None
                ):
                    raise _error("ready run evidence lost provenance-closed coverage")
                bindings.append(
                    _FormalContributionInputBindingV2(
                        formal_family=plan.formal_family,
                        hypothesis_id=coordinate.hypothesis_id,
                        model_id=coordinate.model_id,
                        population=population,
                        coverage=accounting.confirmatory_coverage,
                        coordinate=coordinate,
                    )
                )
        frozen = tuple(bindings)
        expected_keys = {
            (family, coordinate.hypothesis_id, coordinate.model_id)
            for family in MultiSupportFormalFamilyV2
            for coordinate in self._experiment.hypothesis_model_coordinates
        }
        actual_keys = {(item.formal_family, item.hypothesis_id, item.model_id) for item in frozen}
        if len(frozen) != len(expected_keys) or actual_keys != expected_keys:
            raise _error("formal context input registry is not the complete H x M family")
        return frozen

    def _expected_protocol(self) -> FormalAnalysisProtocolV2:
        self._assert_roots()
        return FormalAnalysisProtocolV2._from_formal_context(self)

    def _expected_input_for(
        self,
        binding: _FormalContributionInputBindingV2,
        expected_plan: MultiSupportSimultaneousInferencePlanV2,
    ) -> None:
        expected_coordinate = {
            (item.hypothesis_id, item.model_id): item for item in expected_plan.family.coordinates
        }.get((binding.hypothesis_id, binding.model_id))
        population = {
            item.intervention_bridge.frozen_hypothesis.hypothesis_id: item.population
            for item in self._experiment.protocol_roots
        }.get(binding.hypothesis_id)
        accounting = {
            item.execution_policy_freeze.randomization.population.hypothesis.hypothesis_id: item
            for item in self._evidence.total_assignment_accountings
        }.get(binding.hypothesis_id)
        if (
            expected_coordinate is None
            or population is None
            or accounting is None
            or accounting.confirmatory_coverage is None
            or binding.coordinate != expected_coordinate
            or binding.population != population
            or binding.coverage != accounting.confirmatory_coverage
        ):
            raise _error("formal context contribution input binding failed validation")

    def _contribution_inputs(
        self,
        access: object,
        *,
        formal_family: object,
        hypothesis_id: str,
        model_id: str,
    ) -> tuple[
        PopulationFreezeManifestV2,
        ProvenanceClosedAssignmentCoverageManifestV2,
        SimultaneousTestCoordinateV2,
    ]:
        from secaware.analysis.confirmatory_contributions_v2 import (
            _FORMAL_CONTEXT_CONTRIBUTION_ACCESS,
        )

        if access is not _FORMAL_CONTEXT_CONTRIBUTION_ACCESS:
            raise _error("formal contribution lookup requires the sealed context")
        self._assert_roots()
        if self._phase not in {"inputs", "complete"}:
            raise _error("formal contribution registry is unavailable")
        try:
            family = MultiSupportFormalFamilyV2(formal_family)
        except (TypeError, ValueError):
            raise _error("formal contribution family failed validation") from None
        matches = tuple(
            item
            for item in self._input_bindings
            if (item.formal_family, item.hypothesis_id, item.model_id)
            == (family, hypothesis_id, model_id)
        )
        if len(matches) != 1:
            raise _error("formal contribution lookup is not unique")
        expected_protocol = self._expected_protocol()
        expected_plan = {item.formal_family: item for item in expected_protocol.family_plans}[
            family
        ]
        binding = matches[0]
        self._expected_input_for(binding, expected_plan)
        return binding.population, binding.coverage, binding.coordinate

    def _registry_digest(self) -> str:
        return _digest(
            {
                "experiment_id": self._confirmatory_experiment_freeze_id,
                "evidence_id": self._confirmatory_run_evidence_manifest_id,
                "protocol_id": None
                if self._protocol is None
                else self._protocol.formal_analysis_protocol_id,
                "plans": tuple(
                    (item.formal_family.value, item.plan.inference_plan_id)
                    for item in self._plan_bindings
                ),
                "inputs": tuple(
                    (
                        item.formal_family.value,
                        item.hypothesis_id,
                        item.model_id,
                        item.population.population_freeze_manifest_id,
                        item.coverage.provenance_closed_coverage_manifest_id,
                        item.coordinate.test_coordinate_id,
                    )
                    for item in self._input_bindings
                ),
                "artifacts": tuple(
                    (
                        item.formal_family.value,
                        item.hypothesis_id,
                        item.model_id,
                        item.artifact.contribution_artifact_id,
                    )
                    for item in self._artifact_bindings
                ),
            }
        )

    def _assert_complete_registry(self) -> None:
        self._assert_roots()
        expected_protocol = self._expected_protocol()
        expected_plans = tuple(
            _FormalPlanBindingV2(formal_family=item.formal_family, plan=item)
            for item in expected_protocol.family_plans
        )
        if (
            self._phase != "complete"
            or self._protocol != expected_protocol
            or self._plan_bindings != expected_plans
            or self._registry_sha256 != self._registry_digest()
        ):
            raise _error("formal context deterministic plan registry failed validation")
        if not self._evidence.formal_point_estimation_ready:
            if self._input_bindings or self._artifact_bindings:
                raise _error("non-evaluable formal context contains outcome artifacts")
            return
        expected_keys = {
            (family, coordinate.hypothesis_id, coordinate.model_id)
            for family in MultiSupportFormalFamilyV2
            for coordinate in self._experiment.hypothesis_model_coordinates
        }
        input_keys = {
            (item.formal_family, item.hypothesis_id, item.model_id) for item in self._input_bindings
        }
        artifact_keys = {
            (item.formal_family, item.hypothesis_id, item.model_id)
            for item in self._artifact_bindings
        }
        if (
            len(self._input_bindings) != len(expected_keys)
            or len(self._artifact_bindings) != len(expected_keys)
            or input_keys != expected_keys
            or artifact_keys != expected_keys
        ):
            raise _error("formal context artifact registry is not the complete H x M family")

    def _family_bundle(
        self,
        access: object,
        *,
        formal_family: MultiSupportFormalFamilyV2,
    ) -> tuple[
        MultiSupportSimultaneousInferencePlanV2,
        tuple[ConfirmatoryContributionArtifactV2, ...],
    ]:
        from secaware.analysis.multi_support_simultaneous_v2 import (
            _FORMAL_CONTEXT_RUN_ACCESS,
        )

        if access is not _FORMAL_CONTEXT_RUN_ACCESS:
            raise _error("formal family lookup requires the sealed context")
        self._assert_complete_registry()
        family = MultiSupportFormalFamilyV2(formal_family)
        expected_plan = {
            item.formal_family: item for item in self._expected_protocol().family_plans
        }[family]
        registered_plan = tuple(
            item.plan for item in self._plan_bindings if item.formal_family is family
        )
        if len(registered_plan) != 1 or registered_plan[0] != expected_plan:
            raise _error("formal family plan differs from its deterministic context plan")
        artifact_by_key = {
            (item.hypothesis_id, item.model_id): item.artifact
            for item in self._artifact_bindings
            if item.formal_family is family
        }
        expected_keys = tuple(
            (item.hypothesis_id, item.model_id) for item in expected_plan.family.coordinates
        )
        if len(artifact_by_key) != len(expected_keys) or set(artifact_by_key) != set(expected_keys):
            raise _error("formal family artifact registry is incomplete")
        return expected_plan, tuple(artifact_by_key[key] for key in expected_keys)


def _result_payload(result: FormalConfirmationResultV2) -> dict[str, object]:
    payload = asdict(result)
    payload.pop("formal_confirmation_result_id")
    return payload


def _content_address(result: FormalConfirmationResultV2) -> FormalConfirmationResultV2:
    return FormalConfirmationResultV2(
        formal_confirmation_result_id=_RESULT_PREFIX + _digest(_result_payload(result)),
        confirmatory_experiment_freeze_id=result.confirmatory_experiment_freeze_id,
        confirmatory_run_evidence_manifest_id=(result.confirmatory_run_evidence_manifest_id),
        formal_analysis_protocol_id=result.formal_analysis_protocol_id,
        status=result.status,
        non_evaluable_reason=result.non_evaluable_reason,
        failed_family=result.failed_family,
        expected_assignment_count=result.expected_assignment_count,
        outcome_count=result.outcome_count,
        terminal_failure_count=result.terminal_failure_count,
        terminal_failure_stage_counts=result.terminal_failure_stage_counts,
        family_results=result.family_results,
        coordinate_decisions=result.coordinate_decisions,
        complete_hypothesis_model_family_preserved=(
            result.complete_hypothesis_model_family_preserved
        ),
        assigned_arm_itt_only=result.assigned_arm_itt_only,
        target_changed_and_semantic_validity_diagnostic_only=(
            result.target_changed_and_semantic_validity_diagnostic_only
        ),
        joint_outcome_can_promote_security_label=(result.joint_outcome_can_promote_security_label),
        optional_jci_rfci_marker_per_protocol_present=(
            result.optional_jci_rfci_marker_per_protocol_present
        ),
        optional_evidence_can_promote_confirmatory_label=(
            result.optional_evidence_can_promote_confirmatory_label
        ),
        confirmation_label_rule=result.confirmation_label_rule,
    )


def _base_result(
    *,
    experiment: ConfirmatoryExperimentFreezeV2,
    evidence: ConfirmatoryRunEvidenceManifestV2,
    protocol: FormalAnalysisProtocolV2,
    status: FormalConfirmationStatusV2,
    reason: FormalNonEvaluableReasonV2 | None,
    failed_family: MultiSupportFormalFamilyV2 | None,
    family_results: tuple[FormalFamilyInferenceResultV2, ...],
    decisions: tuple[FormalCoordinateDecisionV2, ...],
) -> FormalConfirmationResultV2:
    provisional = FormalConfirmationResultV2(
        formal_confirmation_result_id="",
        confirmatory_experiment_freeze_id=(experiment.confirmatory_experiment_freeze_id),
        confirmatory_run_evidence_manifest_id=(evidence.confirmatory_run_evidence_manifest_id),
        formal_analysis_protocol_id=protocol.formal_analysis_protocol_id,
        status=status,
        non_evaluable_reason=reason,
        failed_family=failed_family,
        expected_assignment_count=evidence.expected_assignment_count,
        outcome_count=evidence.outcome_count,
        terminal_failure_count=evidence.failure_count,
        terminal_failure_stage_counts=tuple(
            (item.stage, item.count) for item in evidence.terminal_failure_stage_counts
        ),
        family_results=family_results,
        coordinate_decisions=decisions,
        complete_hypothesis_model_family_preserved=True,
        assigned_arm_itt_only=True,
        target_changed_and_semantic_validity_diagnostic_only=True,
        joint_outcome_can_promote_security_label=False,
        optional_jci_rfci_marker_per_protocol_present=False,
        optional_evidence_can_promote_confirmatory_label=False,
        confirmation_label_rule=(
            "primary_secure_yield_then_both_randomized_specificity_contrasts_v1"
        ),
    )
    return _content_address(provisional)


def _direction_status(
    interval: MultiSupportSimultaneousIntervalV2,
    expected: ExpectedDirection,
) -> tuple[bool, bool]:
    if expected is ExpectedDirection.POSITIVE:
        return interval.simultaneous_lower > 0.0, interval.simultaneous_upper < 0.0
    return interval.simultaneous_upper < 0.0, interval.simultaneous_lower > 0.0


def _coordinate_decisions(
    *,
    experiment: ConfirmatoryExperimentFreezeV2,
    protocol: FormalAnalysisProtocolV2,
    family_results: tuple[FormalFamilyInferenceResultV2, ...],
) -> tuple[FormalCoordinateDecisionV2, ...]:
    family_by_name = {item.formal_family: item for item in family_results}
    plan_by_name = {item.formal_family: item for item in protocol.family_plans}
    interval_maps: dict[
        MultiSupportFormalFamilyV2,
        dict[tuple[str, str], tuple[str, MultiSupportSimultaneousIntervalV2]],
    ] = {}
    for name, result in family_by_name.items():
        plan = plan_by_name[name]
        interval_by_id = {
            item.test_coordinate_id: item for item in result.simultaneous_result.intervals
        }
        interval_maps[name] = {
            (coordinate.hypothesis_id, coordinate.model_id): (
                coordinate.test_coordinate_id,
                interval_by_id[coordinate.test_coordinate_id],
            )
            for coordinate in plan.family.coordinates
        }

    expected_by_hypothesis = {
        root.intervention_bridge.frozen_hypothesis.hypothesis_id: (
            root.intervention_bridge.frozen_hypothesis.expected_direction
        )
        for root in experiment.protocol_roots
    }
    decisions = []
    for hm in experiment.hypothesis_model_coordinates:
        key = (hm.hypothesis_id, hm.model_id)
        expected = expected_by_hypothesis[hm.hypothesis_id]
        primary_id, primary_interval = interval_maps[
            MultiSupportFormalFamilyV2.PRIMARY_SECURE_YIELD
        ][key]
        joint_id, joint_interval = interval_maps[MultiSupportFormalFamilyV2.KEY_JOINT][key]
        placebo_id, placebo_interval = interval_maps[
            MultiSupportFormalFamilyV2.SPECIFICITY_PLACEBO
        ][key]
        generic_id, generic_interval = interval_maps[
            MultiSupportFormalFamilyV2.SPECIFICITY_GENERIC
        ][key]
        primary_confirmed, primary_conflicting = _direction_status(
            primary_interval,
            expected,
        )
        placebo_confirmed, _ = _direction_status(placebo_interval, expected)
        generic_confirmed, _ = _direction_status(generic_interval, expected)
        joint_confirmed, joint_conflicting = _direction_status(joint_interval, expected)
        target_specific = primary_confirmed and placebo_confirmed and generic_confirmed
        if target_specific:
            label = FormalCoordinateLabelV2.TARGET_SPECIFIC_POLICY_EFFECT
        elif primary_confirmed:
            label = FormalCoordinateLabelV2.CONFIRMED_POLICY_EFFECT
        elif primary_conflicting:
            label = FormalCoordinateLabelV2.CONFLICTING_POLICY_EFFECT
        else:
            label = FormalCoordinateLabelV2.INCONCLUSIVE
        if joint_confirmed:
            joint = FormalJointInterpretationV2.IMPROVED
        elif joint_conflicting:
            joint = FormalJointInterpretationV2.HARMED
        else:
            joint = FormalJointInterpretationV2.INCONCLUSIVE
        decisions.append(
            FormalCoordinateDecisionV2(
                hypothesis_model_coordinate_id=hm.hypothesis_model_coordinate_id,
                hypothesis_id=hm.hypothesis_id,
                model_id=hm.model_id,
                expected_direction=expected,
                label=label,
                primary_confirmed=primary_confirmed,
                target_vs_placebo_confirmed=placebo_confirmed,
                target_vs_generic_confirmed=generic_confirmed,
                target_specificity_confirmed=target_specific,
                joint_interpretation=joint,
                primary_test_coordinate_id=primary_id,
                joint_test_coordinate_id=joint_id,
                placebo_test_coordinate_id=placebo_id,
                generic_test_coordinate_id=generic_id,
                label_basis=("randomized_assigned_arm_itt_simultaneous_intervals_only_v1"),
            )
        )
    return tuple(decisions)


def _run_formal(
    experiment_freeze: ConfirmatoryExperimentFreezeV2,
    run_evidence: ConfirmatoryRunEvidenceManifestV2,
) -> FormalConfirmationResultV2:
    context = _ValidatedFormalContextV2._from_roots(
        experiment_freeze,
        run_evidence,
        access=_FORMAL_ENTRY_CONTEXT_ACCESS,
    )
    experiment = context.experiment
    evidence = context.evidence
    protocol = context.protocol
    if not evidence.formal_point_estimation_ready:
        return _base_result(
            experiment=experiment,
            evidence=evidence,
            protocol=protocol,
            status=FormalConfirmationStatusV2.NON_EVALUABLE,
            reason=FormalNonEvaluableReasonV2.TERMINAL_INFRASTRUCTURE_FAILURE,
            failed_family=None,
            family_results=(),
            decisions=(),
        )

    family_results = []
    for formal_family in MultiSupportFormalFamilyV2:
        try:
            plan, artifacts, simultaneous = _run_frozen_domain_from_formal_context_v2(
                context,
                formal_family,
            )
        except ValueError:
            return _base_result(
                experiment=experiment,
                evidence=evidence,
                protocol=protocol,
                status=FormalConfirmationStatusV2.NON_EVALUABLE,
                reason=FormalNonEvaluableReasonV2.INFERENCE_UNDEFINED,
                failed_family=formal_family,
                family_results=(),
                decisions=(),
            )
        family_results.append(
            FormalFamilyInferenceResultV2(
                formal_family=plan.formal_family,
                inference_plan_id=plan.inference_plan_id,
                family_id=plan.family.family_id,
                contribution_artifact_ids=tuple(
                    item.contribution_artifact_id for item in artifacts
                ),
                contribution_artifacts=artifacts,
                simultaneous_result=simultaneous,
            )
        )
    frozen_family_results = tuple(family_results)
    decisions = _coordinate_decisions(
        experiment=experiment,
        protocol=protocol,
        family_results=frozen_family_results,
    )
    return _base_result(
        experiment=experiment,
        evidence=evidence,
        protocol=protocol,
        status=FormalConfirmationStatusV2.EVALUATED,
        reason=None,
        failed_family=None,
        family_results=frozen_family_results,
        decisions=decisions,
    )


def run_formal_confirmation_v2(
    experiment_freeze: ConfirmatoryExperimentFreezeV2,
    run_evidence: ConfirmatoryRunEvidenceManifestV2,
) -> FormalConfirmationResultV2:
    """Run the four immutable formal families from two provenance roots only."""

    return _run_formal(experiment_freeze, run_evidence)


def validate_formal_confirmation_result_v2(
    experiment_freeze: ConfirmatoryExperimentFreezeV2,
    run_evidence: ConfirmatoryRunEvidenceManifestV2,
    result: FormalConfirmationResultV2,
) -> FormalConfirmationResultV2:
    """Replay the complete formal analysis and require exact artifact equality."""

    if type(result) is not FormalConfirmationResultV2:
        raise _error("formal confirmation result artifact failed validation")
    expected = _run_formal(experiment_freeze, run_evidence)
    if result != expected:
        raise _error("formal confirmation result artifact failed validation")
    return result


__all__ = [
    "FormalConfirmationResultV2",
    "FormalCoordinateDecisionV2",
    "FormalFamilyInferenceResultV2",
    "run_formal_confirmation_v2",
    "validate_formal_confirmation_result_v2",
]

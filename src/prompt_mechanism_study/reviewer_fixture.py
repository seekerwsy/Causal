"""Fixed, non-claim inputs and offline responses for the reviewer smoke.

The fixture supplies data, never Security Oracle labels or Measurement records.
The workflow sends its responses through the normal measurement functions.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.prioritization import (
    AtomicCandidateUniverseManifest,
    AtomicFCIBootstrapEvidence,
    AtomicShadowPlan,
    ConfirmationDispatchManifest,
    DiscoveryObservation,
)
from prompt_mechanism_study.discovery_population import DiscoveryPopulationLineage
from prompt_mechanism_study.randomization import (
    ATOMIC_CONFIRMATORY_ARMS,
    TargetRandomizationPlan,
    TargetTaskArmVariant,
    TargetTaskBundle,
    allocate_target_realizations,
)
from prompt_mechanism_study.records import content_hash, content_id
from prompt_mechanism_study.representation import AtomicPolicyKey, DataRoleManifest
from prompt_mechanism_study.study_planning import RQ1BudgetQualification
from prompt_mechanism_study.verification.integrity import _decode_target_value


@dataclass(frozen=True, slots=True)
class ReviewerSmokeFixture:
    manifest: DataRoleManifest
    budget: RQ1BudgetQualification
    population_lineage: DiscoveryPopulationLineage
    atomic_policy: AtomicPolicyKey
    atomic_universe: AtomicCandidateUniverseManifest
    atomic_observations: tuple[DiscoveryObservation, ...]
    atomic_plan: AtomicShadowPlan
    atomic_fci_evidence: AtomicFCIBootstrapEvidence
    security_profile_id: str
    source_task_prompt: str
    functional_requirement: str
    functional_response: str
    generation_responses: tuple[tuple[str, str, str], ...]

    def variant_prompt(self, policy_key: str, task_unit_id: str, arm: str) -> str:
        return (f"{self.source_task_prompt}\nSynthetic fixture policy: {policy_key}"
                f"\nTask unit: {task_unit_id}\nAssigned arm: {arm}")

    def complete(self, request, evaluator, prompt) -> bytes:
        """Return frozen raw responses; this callback cannot contact a provider."""
        if evaluator != {"model_id": self.atomic_plan.model_id}:
            raise ValueError("smoke evaluator drift")
        if "arm" in request:
            responses = {(unit, arm): raw for unit, arm, raw in self.generation_responses}
            return responses[(request["task_unit_id"], request["arm"])].encode("utf-8")
        if not request.get("program_lines") or not all(request.get("blindness", {}).values()):
            raise ValueError("smoke functional review must contain code and preserve blindness")
        return self.functional_response.encode("utf-8")

    def task_bundles(
        self, dispatch: ConfirmationDispatchManifest, plan: TargetRandomizationPlan
    ) -> tuple[TargetTaskBundle, ...]:
        allocated = allocate_target_realizations(plan)
        records = {record.policy_key: record for record in dispatch.records}
        tracks = {entry.candidate.policy_key: entry.track for entry in dispatch.union.entries}
        weights = {
            (policy, realization): weight
            for policy, realization, weight in plan.realization_weights
        }
        bundles = []
        for policy, unit, stratum in plan.allocation_tasks:
            record, track = (records[policy], tracks[policy])
            realization = allocated[policy, unit]
            arms = ATOMIC_CONFIRMATORY_ARMS
            bundles.append(
                TargetTaskBundle(
                    policy,
                    track,
                    unit,
                    f"{unit}-instance",
                    stratum,
                    realization,
                    content_id("reviewer_smoke_task_bundle_", (policy, unit)),
                    record.protocol_record_id,
                    1.0,
                    weights[policy, realization],
                    tuple(
                        (
                            TargetTaskArmVariant(
                                arm, content_hash(self.variant_prompt(policy, unit, arm.value))
                            )
                            for arm in arms
                        )
                    ),
                )
            )
        return tuple(
            sorted(
                bundles, key=lambda row: (row.policy_key, row.task_unit_id, row.task_instance_id)
            )
        )


def load_reviewer_smoke_fixture() -> ReviewerSmokeFixture:
    path = Path(__file__).with_name("fixtures") / "reviewer_smoke.json"
    return _decode_target_value(read_json(path), ReviewerSmokeFixture, path.name)

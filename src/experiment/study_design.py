"""Direct prospective inputs for the non-claim reviewer experiment.

No receipt can activate a formal study. The active protocol remains SPECIFIED_DRAFT.
Numerical power planning is available separately in study_planning.
"""
from __future__ import annotations
from dataclasses import dataclass
from prompt_mechanism_study.data.discovery_population import DiscoveryPopulationLineage
from prompt_mechanism_study.experiment.inference import TargetITTPlan
from prompt_mechanism_study.experiment.randomization import TargetRandomizationPlan, TargetTaskBundle
from prompt_mechanism_study.discovery.prioritization import ConfirmationDispatchManifest
from prompt_mechanism_study.tsg.representation import DataRoleManifest
from prompt_mechanism_study.records import content_id


@dataclass(frozen=True, slots=True)
class StudyConfig:
    """Inputs fixed before selection; full values are stored, not chains of receipts."""
    manifest: DataRoleManifest
    population_lineage: DiscoveryPopulationLineage
    inference_plan: TargetITTPlan
    model_ids: tuple[str, ...]
    selector_ids: tuple[str, ...]
    top_k: int
    atomic_total_block_slots: int
    generation_call_limit: int
    discovery_inputs: dict
    protocol_status: str = "SPECIFIED_DRAFT"

    def __post_init__(self):
        if self.protocol_status != "SPECIFIED_DRAFT":
            raise ValueError("formal execution is unavailable under SPECIFIED_DRAFT")
        if any(type(n) is not int or n < 1 for n in
               (self.top_k, self.atomic_total_block_slots, self.generation_call_limit)):
            raise ValueError("study dimensions and call limit must be positive integers")
        if not self.model_ids or not self.selector_ids:
            raise ValueError("study requires models and selectors")

    @property
    def study_id(self):
        return content_id("study_", self)


@dataclass(frozen=True, slots=True)
class ConfirmationInputs:
    """Selected policies, task eligibility, variants and randomization fixed before measurement."""
    study_id: str
    dispatch: ConfirmationDispatchManifest
    randomization_plan: TargetRandomizationPlan
    task_bundles: tuple[TargetTaskBundle, ...]
    measurement_contract: dict

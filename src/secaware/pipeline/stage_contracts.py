"""Dynamic contract digests for persisted causal discovery stages."""

from __future__ import annotations

import importlib.metadata

from secaware.causal.variable_catalog import VARIABLE_CATALOG_SHA256
from secaware.config import (
    AppConfig,
    FCIDiscoveryConfig,
    GenerationConfig,
    InterventionConfig,
    RandomizationConfig,
    TSGConfig,
)
from secaware.pipeline.artifact import canonical_sha256
from secaware.randomness import RNG_VERSION
from secaware.schema.causal import (
    BackgroundKnowledgeRecord,
    BootstrapDrawRecord,
    BootstrapFailureRecord,
    BootstrapPAGRecord,
    CausalExclusionRecord,
    CausalObservationRecord,
    CausalTableRecord,
    DiscoveryFailureRecord,
    FrozenHypothesisRecord,
    PAGRecord,
    PathPatternRecord,
    PathSupportRecord,
)
from secaware.schema.generation import GenerationRequestRecord
from secaware.schema.records import CanonicalGeneratedCodeRecord, PromptRecord
from secaware.schema.experiments import (
    AllowedDeltaRecord,
    AssignmentRecord,
    AssignmentExecutionRecord,
    ArmSpecRecord,
    ConfirmationProtocolInstanceRecord,
    ConfirmationProtocolRecord,
    FeatureTransition,
    FunctionalOutcomeContractRecord,
    GraphDeltaRecord,
    ExperimentalUnit,
    LengthMatchRecord,
    PreRandomizationExclusionRecord,
    PromptVariantRecord,
    RandomizationManifestRecord,
    TargetInstanceRecord,
    TargetSpecRecord,
)
from secaware.schema.prompt_extraction import PromptExtractionProposalRecord
from secaware.schema.tsg import PromptTSGRecord
from secaware.tsg.contract import PROMPT_TSG_STAGE_CONTRACT_SHA256
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256


_CAUSAL_TABLE_STAGE = "assemble-causal-tables"
_FCI_STAGE = "fci-discovery"
_PROMPT_VARIANT_STAGE = "build-confirmation-variants"
_RANDOMIZATION_STAGE = "randomize-confirmation"
_CONFIRMATION_GENERATION_STAGE = "generate-confirmation"


def _schema_sha256(model: type) -> str:
    return canonical_sha256(model.model_json_schema())


def _causal_learn_version() -> str:
    try:
        return importlib.metadata.version("causal-learn")
    except importlib.metadata.PackageNotFoundError:
        return "missing"


def discovery_stage_contract_payload(stage: str) -> dict[str, object]:
    """Return the complete code-external version binding for one discovery stage."""
    common: dict[str, object] = {
        "stage": stage,
        "prompt_feature_catalog_sha256": PROMPT_FEATURE_CATALOG_SHA256,
        "variable_catalog_sha256": VARIABLE_CATALOG_SHA256,
        "prompt_tsg_stage_contract_sha256": PROMPT_TSG_STAGE_CONTRACT_SHA256,
    }
    if stage == _CAUSAL_TABLE_STAGE:
        return {
            **common,
            "table_schema": _schema_sha256(CausalTableRecord),
            "observation_schema": _schema_sha256(CausalObservationRecord),
            "exclusion_schema": _schema_sha256(CausalExclusionRecord),
            "canonical_observed_code_schema": _schema_sha256(CanonicalGeneratedCodeRecord),
        }
    if stage == _FCI_STAGE:
        return {
            **common,
            "causal_learn_required_version": "0.1.4.7",
            "causal_learn_runtime_version": _causal_learn_version(),
            "fci_config_schema": _schema_sha256(FCIDiscoveryConfig),
            "rng_version": RNG_VERSION,
            "background_schema": _schema_sha256(BackgroundKnowledgeRecord),
            "pag_schema": _schema_sha256(PAGRecord),
            "draw_schema": _schema_sha256(BootstrapDrawRecord),
            "bootstrap_pag_schema": _schema_sha256(BootstrapPAGRecord),
            "bootstrap_failure_schema": _schema_sha256(BootstrapFailureRecord),
            "path_schema": _schema_sha256(PathPatternRecord),
            "path_support_schema": _schema_sha256(PathSupportRecord),
            "freeze_schema": _schema_sha256(FrozenHypothesisRecord),
            "discovery_failure_schema": _schema_sha256(DiscoveryFailureRecord),
        }
    raise ValueError("unknown discovery stage contract")


def discovery_stage_contract_sha256(stage: str) -> str | None:
    if stage not in {_CAUSAL_TABLE_STAGE, _FCI_STAGE}:
        return None
    return canonical_sha256(discovery_stage_contract_payload(stage))


def prompt_variant_stage_contract_payload() -> dict[str, object]:
    """Return all code-external contracts governing pre-randomization freeze."""

    # Lazy imports avoid RunStore -> stage_contracts -> intervention -> freeze ->
    # RunStore during process initialization.
    from secaware.intervention.attestation import PromptRoleAttestationRecord
    from secaware.intervention.executors import (
        DETERMINISTIC_INTERVENTION_POLICY_SHA256,
        INTERVENTION_EXECUTOR_OUTPUT_SCHEMA_SHA256,
        INTERVENTION_EXECUTOR_SYSTEM_TEMPLATE_SHA256,
        PromptCandidate,
    )
    from secaware.intervention.graph_patch import IntendedGraphPatchRecord
    from secaware.intervention.variant_validation import BLIND_EXTRACTION_ORDER_VERSION

    return {
        "stage": _PROMPT_VARIANT_STAGE,
        "contract_version": "prompt-variant-freeze-v2",
        "blind_extraction_order_version": BLIND_EXTRACTION_ORDER_VERSION,
        "prompt_feature_catalog_sha256": PROMPT_FEATURE_CATALOG_SHA256,
        "prompt_tsg_stage_contract_sha256": PROMPT_TSG_STAGE_CONTRACT_SHA256,
        "deterministic_executor_policy_sha256": DETERMINISTIC_INTERVENTION_POLICY_SHA256,
        "executor_template_sha256": INTERVENTION_EXECUTOR_SYSTEM_TEMPLATE_SHA256,
        "executor_output_schema_sha256": INTERVENTION_EXECUTOR_OUTPUT_SCHEMA_SHA256,
        "app_config_schema": _schema_sha256(AppConfig),
        "intervention_config_schema": _schema_sha256(InterventionConfig),
        "extractor_config_schema": _schema_sha256(TSGConfig),
        "candidate_schema": _schema_sha256(PromptCandidate),
        "prompt_schema": _schema_sha256(PromptRecord),
        "attestation_schema": _schema_sha256(PromptRoleAttestationRecord),
        "functional_contract_schema": _schema_sha256(FunctionalOutcomeContractRecord),
        "frozen_hypothesis_schema": _schema_sha256(FrozenHypothesisRecord),
        "feature_transition_schema": _schema_sha256(FeatureTransition),
        "allowed_delta_schema": _schema_sha256(AllowedDeltaRecord),
        "arm_schema": _schema_sha256(ArmSpecRecord),
        "target_schema": _schema_sha256(TargetSpecRecord),
        "target_instance_schema": _schema_sha256(TargetInstanceRecord),
        "protocol_schema": _schema_sha256(ConfirmationProtocolRecord),
        "protocol_instance_schema": _schema_sha256(ConfirmationProtocolInstanceRecord),
        "patch_schema": _schema_sha256(IntendedGraphPatchRecord),
        "proposal_schema": _schema_sha256(PromptExtractionProposalRecord),
        "prompt_tsg_schema": _schema_sha256(PromptTSGRecord),
        "delta_schema": _schema_sha256(GraphDeltaRecord),
        "variant_schema": _schema_sha256(PromptVariantRecord),
        "length_match_schema": _schema_sha256(LengthMatchRecord),
        "exclusion_schema": _schema_sha256(PreRandomizationExclusionRecord),
        "length_metric": "canonical_changed_span_utf8_bytes_v1",
    }


def prompt_variant_stage_contract_sha256(stage: str) -> str | None:
    if stage != _PROMPT_VARIANT_STAGE:
        return None
    return canonical_sha256(prompt_variant_stage_contract_payload())


def randomization_stage_contract_payload() -> dict[str, object]:
    """Bind every direct schema/config/RNG contract for assignment freezing."""

    from secaware.intervention.graph_patch import IntendedGraphPatchRecord
    from secaware.pipeline.manifest import StageManifest

    return {
        "stage": _RANDOMIZATION_STAGE,
        "contract_version": "confirmation-randomization-v1",
        "rng_version": RNG_VERSION,
        "prompt_feature_catalog_sha256": PROMPT_FEATURE_CATALOG_SHA256,
        "app_config_schema": _schema_sha256(AppConfig),
        "generation_config_schema": _schema_sha256(GenerationConfig),
        "randomization_config_schema": _schema_sha256(RandomizationConfig),
        "hypothesis_schema": _schema_sha256(FrozenHypothesisRecord),
        "target_schema": _schema_sha256(TargetSpecRecord),
        "target_instance_schema": _schema_sha256(TargetInstanceRecord),
        "protocol_schema": _schema_sha256(ConfirmationProtocolRecord),
        "protocol_instance_schema": _schema_sha256(ConfirmationProtocolInstanceRecord),
        "patch_schema": _schema_sha256(IntendedGraphPatchRecord),
        "proposal_schema": _schema_sha256(PromptExtractionProposalRecord),
        "prompt_tsg_schema": _schema_sha256(PromptTSGRecord),
        "graph_delta_schema": _schema_sha256(GraphDeltaRecord),
        "variant_schema": _schema_sha256(PromptVariantRecord),
        "length_match_schema": _schema_sha256(LengthMatchRecord),
        "exclusion_schema": _schema_sha256(PreRandomizationExclusionRecord),
        "producer_manifest_schema": _schema_sha256(StageManifest),
        "experimental_unit_schema": _schema_sha256(ExperimentalUnit),
        "assignment_schema": _schema_sha256(AssignmentRecord),
        "manifest_schema": _schema_sha256(RandomizationManifestRecord),
    }


def randomization_stage_contract_sha256(stage: str) -> str | None:
    if stage != _RANDOMIZATION_STAGE:
        return None
    return canonical_sha256(randomization_stage_contract_payload())


def confirmation_generation_stage_contract_payload() -> dict[str, object]:
    """Bind assignment generation to every direct schema/config/provider contract."""

    from secaware.pipeline.manifest import StageManifest
    from secaware.pipeline.stages.confirmation_generation import (
        CONFIRMATION_PROVIDER_POLICY_VERSION,
    )

    return {
        "stage": _CONFIRMATION_GENERATION_STAGE,
        "contract_version": "assignment-bound-confirmation-generation-v1",
        "provider_policy_version": CONFIRMATION_PROVIDER_POLICY_VERSION,
        "app_config_schema": _schema_sha256(AppConfig),
        "generation_config_schema": _schema_sha256(GenerationConfig),
        "request_schema": _schema_sha256(GenerationRequestRecord),
        "code_schema": _schema_sha256(CanonicalGeneratedCodeRecord),
        "execution_schema": _schema_sha256(AssignmentExecutionRecord),
        "assignment_schema": _schema_sha256(AssignmentRecord),
        "variant_schema": _schema_sha256(PromptVariantRecord),
        "randomization_manifest_schema": _schema_sha256(RandomizationManifestRecord),
        "producer_manifest_schema": _schema_sha256(StageManifest),
    }


def confirmation_generation_stage_contract_sha256(stage: str) -> str | None:
    if stage != _CONFIRMATION_GENERATION_STAGE:
        return None
    return canonical_sha256(confirmation_generation_stage_contract_payload())


__all__ = [
    "discovery_stage_contract_payload",
    "discovery_stage_contract_sha256",
    "prompt_variant_stage_contract_payload",
    "prompt_variant_stage_contract_sha256",
    "randomization_stage_contract_payload",
    "randomization_stage_contract_sha256",
    "confirmation_generation_stage_contract_payload",
    "confirmation_generation_stage_contract_sha256",
]

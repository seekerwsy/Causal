"""Dynamic contract digests for persisted causal discovery stages."""

from __future__ import annotations

import importlib.metadata
import re

from secaware.causal.variable_catalog import VARIABLE_CATALOG_SHA256
from secaware.config import (
    AppConfig,
    FCIDiscoveryConfig,
    GenerationConfig,
    InterventionConfig,
    OracleConfig,
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
from secaware.schema.oracle import OracleRecord
from secaware.schema.outcomes import FunctionalOutcomeRecord
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
_CONFIRMATION_ORACLE_STAGE = "run-oracle-confirmation"
_FUNCTIONAL_OUTCOME_IMPORT_STAGE = "import-functional-outcomes"

CONFIRMATION_STAGE_ORDER = (
    "build-confirmation-variants",
    "randomize-confirmation",
    "generate-confirmation",
    "run-oracle-confirmation",
    _FUNCTIONAL_OUTCOME_IMPORT_STAGE,
    "assemble-assignment-outcomes",
    "estimate-confirmation-effects",
    "jci-confirmation",
    "rfci-confirmation",
    "mechanisms",
    "reporting",
)
_CONFIRMATION_STAGE_MANIFEST_FAMILIES = (
    ("build-confirmation-variants",),
    ("randomize-confirmation",),
    ("generate-confirmation",),
    ("run-oracle-confirmation",),
    (_FUNCTIONAL_OUTCOME_IMPORT_STAGE,),
    (
        "assemble-assignment-outcomes",
        "assignment-outcomes",
        "confirm",
        "confirmation-outcomes",
        "confirm-outcomes",
    ),
    (
        "effects",
        "estimate-effects",
        "estimate-confirmation-effects",
        "confirmation-effects",
        "confirm-effects",
    ),
    ("analyze-jci", "jci", "jci-analysis", "jci-confirmation"),
    ("analyze-rfci", "rfci", "rfci-analysis", "rfci-confirmation"),
    ("mechanisms",),
    ("report", "reports", "reporting"),
)
_STAGE_VERSION_AFFIX = re.compile(
    r"^(?:v[1-9][0-9]{0,5}|20[0-9]{2}(?:-[01][0-9](?:-[0-3][0-9])?)?)$"
)


def _matches_stage_manifest_family(value: str, family: str) -> bool:
    if value == family:
        return True
    if value.startswith(family + "-"):
        return _STAGE_VERSION_AFFIX.fullmatch(value[len(family) + 1 :]) is not None
    if value.endswith("-" + family):
        return _STAGE_VERSION_AFFIX.fullmatch(value[: -(len(family) + 1)]) is not None
    return False


def confirmation_stage_is_downstream(stage_name: str, *, after: str) -> bool:
    """Classify only declared confirmation-stage manifest families and bounded variants."""

    if (
        type(stage_name) is not str
        or type(after) is not str
        or after not in CONFIRMATION_STAGE_ORDER
    ):
        return False
    candidate = stage_name.casefold()
    if candidate != stage_name or not 1 <= len(candidate) <= 128:
        return False
    for index, families in enumerate(_CONFIRMATION_STAGE_MANIFEST_FAMILIES):
        if any(_matches_stage_manifest_family(candidate, family) for family in families):
            return index > CONFIRMATION_STAGE_ORDER.index(after)
    return False


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


def confirmation_generation_stage_contract_payload(
    generation_config: GenerationConfig | None = None,
) -> dict[str, object]:
    """Bind assignment generation to every direct schema/config/provider contract."""

    from secaware.pipeline.manifest import StageManifest
    from secaware.pipeline.stages import confirmation_generation as confirmation_stage
    from secaware.generation.confirmation import CONFIRMATION_PROVIDER_RESULT_POLICY_SHA256
    from secaware.generation.openai_compatible_provider import (
        openai_provider_runtime_payload,
    )
    from secaware.schema.generation import GenerationProvenance, ProviderResultEnvelope

    runtime_payload: object = {"provider": "unbound"}
    if generation_config is not None:
        if generation_config.provider == "openai_compatible":
            runtime_payload = openai_provider_runtime_payload()
        else:
            runtime_payload = {
                "provider": generation_config.provider,
                "implementation": "locked-confirmation-provider-v1",
            }

    return {
        "stage": _CONFIRMATION_GENERATION_STAGE,
        "contract_version": "assignment-bound-confirmation-generation-v1",
        "provider_policy_version": confirmation_stage.CONFIRMATION_PROVIDER_POLICY_VERSION,
        "provider_factory_version": confirmation_stage.CONFIRMATION_PROVIDER_FACTORY_VERSION,
        "provider_response_contract_version": confirmation_stage.CONFIRMATION_PROVIDER_RESPONSE_VERSION,
        "provider_result_policy_sha256": CONFIRMATION_PROVIDER_RESULT_POLICY_SHA256,
        "provider_runtime": runtime_payload,
        "runtime_callable_bundle": confirmation_stage.confirmation_runtime_callable_contract(),
        "output_policy": confirmation_stage.confirmation_output_policy_contract(),
        "app_config_schema": _schema_sha256(AppConfig),
        "generation_config_schema": _schema_sha256(GenerationConfig),
        "request_schema": _schema_sha256(GenerationRequestRecord),
        "provider_provenance_schema": _schema_sha256(GenerationProvenance),
        "provider_result_schema": _schema_sha256(ProviderResultEnvelope),
        "code_schema": _schema_sha256(CanonicalGeneratedCodeRecord),
        "execution_schema": _schema_sha256(AssignmentExecutionRecord),
        "assignment_schema": _schema_sha256(AssignmentRecord),
        "variant_schema": _schema_sha256(PromptVariantRecord),
        "randomization_manifest_schema": _schema_sha256(RandomizationManifestRecord),
        "producer_manifest_schema": _schema_sha256(StageManifest),
    }


def confirmation_generation_stage_contract_sha256(
    stage: str,
    generation_config: GenerationConfig | None = None,
) -> str | None:
    if stage != _CONFIRMATION_GENERATION_STAGE:
        return None
    return canonical_sha256(confirmation_generation_stage_contract_payload(generation_config))


def confirmation_oracle_stage_contract_payload() -> dict[str, object]:
    """Bind the randomized Oracle to every direct schema and runtime contract."""

    from secaware.pipeline.manifest import StageManifest
    from secaware.pipeline.stages import confirmation_oracle as oracle_stage

    return {
        "stage": _CONFIRMATION_ORACLE_STAGE,
        "contract_version": "assignment-bound-confirmation-oracle-v1",
        "runtime_callable_bundle": oracle_stage.confirmation_oracle_runtime_callable_contract(),
        "output_policy": oracle_stage.confirmation_oracle_output_policy_contract(),
        "app_config_schema": _schema_sha256(AppConfig),
        "oracle_config_schema": _schema_sha256(OracleConfig),
        "target_schema": _schema_sha256(TargetSpecRecord),
        "target_instance_schema": _schema_sha256(TargetInstanceRecord),
        "protocol_schema": _schema_sha256(ConfirmationProtocolRecord),
        "protocol_instance_schema": _schema_sha256(ConfirmationProtocolInstanceRecord),
        "variant_schema": _schema_sha256(PromptVariantRecord),
        "pre_randomization_exclusion_schema": _schema_sha256(PreRandomizationExclusionRecord),
        "frozen_hypothesis_schema": _schema_sha256(FrozenHypothesisRecord),
        "randomization_manifest_schema": _schema_sha256(RandomizationManifestRecord),
        "assignment_schema": _schema_sha256(AssignmentRecord),
        "request_schema": _schema_sha256(GenerationRequestRecord),
        "execution_schema": _schema_sha256(AssignmentExecutionRecord),
        "code_schema": _schema_sha256(CanonicalGeneratedCodeRecord),
        "oracle_schema": _schema_sha256(OracleRecord),
        "producer_manifest_schema": _schema_sha256(StageManifest),
    }


def confirmation_oracle_stage_contract_sha256(stage: str) -> str | None:
    if stage != _CONFIRMATION_ORACLE_STAGE:
        return None
    return canonical_sha256(confirmation_oracle_stage_contract_payload())


def functional_outcome_import_stage_contract_payload() -> dict[str, object]:
    """Bind external functional imports to frozen M5 and output schemas."""

    from secaware.pipeline.manifest import StageManifest

    return {
        "stage": _FUNCTIONAL_OUTCOME_IMPORT_STAGE,
        "contract_version": "independent-functional-outcome-import-v1",
        "app_config_schema": _schema_sha256(AppConfig),
        "assignment_schema": _schema_sha256(AssignmentRecord),
        "randomization_manifest_schema": _schema_sha256(RandomizationManifestRecord),
        "protocol_schema": _schema_sha256(ConfirmationProtocolRecord),
        "functional_contract_schema": _schema_sha256(FunctionalOutcomeContractRecord),
        "functional_outcome_schema": _schema_sha256(FunctionalOutcomeRecord),
        "producer_manifest_schema": _schema_sha256(StageManifest),
        "confirmation_stage_order": list(CONFIRMATION_STAGE_ORDER),
        "confirmation_stage_manifest_families": [
            list(families) for families in _CONFIRMATION_STAGE_MANIFEST_FAMILIES
        ],
        "stage_version_affix_pattern": _STAGE_VERSION_AFFIX.pattern,
    }


def functional_outcome_import_stage_contract_sha256(stage: str) -> str | None:
    if stage != _FUNCTIONAL_OUTCOME_IMPORT_STAGE:
        return None
    return canonical_sha256(functional_outcome_import_stage_contract_payload())


__all__ = [
    "CONFIRMATION_STAGE_ORDER",
    "confirmation_stage_is_downstream",
    "discovery_stage_contract_payload",
    "discovery_stage_contract_sha256",
    "prompt_variant_stage_contract_payload",
    "prompt_variant_stage_contract_sha256",
    "randomization_stage_contract_payload",
    "randomization_stage_contract_sha256",
    "confirmation_generation_stage_contract_payload",
    "confirmation_generation_stage_contract_sha256",
    "confirmation_oracle_stage_contract_payload",
    "confirmation_oracle_stage_contract_sha256",
    "functional_outcome_import_stage_contract_payload",
    "functional_outcome_import_stage_contract_sha256",
]

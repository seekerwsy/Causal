"""Dynamic contract digests for persisted causal discovery stages."""

from __future__ import annotations

import importlib.metadata

from secaware.causal.variable_catalog import (
    OBSERVATIONAL_VARIABLE_CATALOG_SHA256,
    VARIABLE_CATALOG_SHA256,
)
from secaware.config import FCIDiscoveryConfig
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
from secaware.tsg.contract import PROMPT_TSG_STAGE_CONTRACT_SHA256
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256


_CAUSAL_TABLE_STAGE = "assemble-causal-tables"
_FCI_STAGE = "fci-discovery"


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
        "observational_variable_catalog_sha256": OBSERVATIONAL_VARIABLE_CATALOG_SHA256,
        "prompt_tsg_stage_contract_sha256": PROMPT_TSG_STAGE_CONTRACT_SHA256,
    }
    if stage == _CAUSAL_TABLE_STAGE:
        return {
            **common,
            "table_schema": _schema_sha256(CausalTableRecord),
            "observation_schema": _schema_sha256(CausalObservationRecord),
            "exclusion_schema": _schema_sha256(CausalExclusionRecord),
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


__all__ = [
    "discovery_stage_contract_payload",
    "discovery_stage_contract_sha256",
]

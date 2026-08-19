"""Public builders for frozen natural-Prompt v2 causal tables."""

from __future__ import annotations

from secaware.schema.discovery_v2 import (
    DiscoveryAnalysisKindV2,
    NaturalDiscoveryTableArtifactV2,
    NaturalDiscoveryTableSpecV2,
)
from secaware.schema.runtime_v2 import (
    NaturalCausalObservationRecordV2,
    RuntimeProducerChainRecordV2,
)


def build_natural_discovery_table_v2(
    *,
    table_spec: NaturalDiscoveryTableSpecV2,
    observations: tuple[NaturalCausalObservationRecordV2, ...],
    producer_chains: tuple[RuntimeProducerChainRecordV2, ...],
) -> NaturalDiscoveryTableArtifactV2:
    """Build one exact table artifact or fail closed on any coverage/provenance drift."""

    return NaturalDiscoveryTableArtifactV2.from_components(
        table_spec=table_spec,
        observations=observations,
        producer_chains=producer_chains,
    )


def categorical_rows_v2(
    table: NaturalDiscoveryTableArtifactV2,
) -> tuple[tuple[int, ...], ...]:
    """Return audit rows except for two-level tables, which require a frozen draw."""

    checked = NaturalDiscoveryTableArtifactV2.model_validate(table, strict=True)
    if checked.table_spec.analysis_kind is DiscoveryAnalysisKindV2.TWO_LEVEL:
        raise ValueError(
            "raw two-level observations cannot feed CI; use a frozen cluster/slot draw"
        )
    return checked.categorical_rows()


__all__ = ["build_natural_discovery_table_v2", "categorical_rows_v2"]

"""Prompt-path cards that preserve PAG endpoint uncertainty."""

from __future__ import annotations

from collections import defaultdict
from typing import Sequence

from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.causal import FrozenHypothesisRecord
from secaware.schema.outcomes import ITTEffectRecord


def build_hypothesis_cards(
    hypotheses: Sequence[FrozenHypothesisRecord],
    effects: Sequence[ITTEffectRecord],
) -> tuple[dict[str, object], ...]:
    effects_by_hypothesis: dict[str, list[ITTEffectRecord]] = defaultdict(list)
    for effect in effects:
        effects_by_hypothesis[effect.hypothesis_id].append(effect)
    unknown = set(effects_by_hypothesis) - {item.hypothesis_id for item in hypotheses}
    if unknown:
        raise ValueError("hypothesis card provenance failed validation")

    cards: list[dict[str, object]] = []
    for hypothesis in sorted(hypotheses, key=lambda item: item.hypothesis_id):
        local_effects = list(
            sorted(effects_by_hypothesis[hypothesis.hypothesis_id], key=lambda item: item.effect_id)
        )
        payload: dict[str, object] = {
            "schema_version": "1.0",
            "hypothesis_id": hypothesis.hypothesis_id,
            "hypothesis_sha256": hypothesis.hypothesis_sha256,
            "target_feature_id": hypothesis.target_feature_id,
            "feature_family": hypothesis.feature_family.value,
            "permitted_operations": [item.value for item in hypothesis.permitted_operations],
            "scope_id": hypothesis.scope_id,
            "cwe": hypothesis.cwe,
            "model_id": hypothesis.model_id,
            "outcome_variable_id": hypothesis.outcome_variable_id,
            "reference_pag_id": hypothesis.reference_pag_id,
            "hypothesis_path": hypothesis.path.model_dump(mode="json"),
            "bootstrap_support": {
                "numerator": hypothesis.support_numerator,
                "denominator": hypothesis.support_denominator,
            },
            "source_commitments": {
                "table_sha256": hypothesis.table_sha256,
                "catalog_sha256": hypothesis.catalog_sha256,
                "extractor_policy_sha256": hypothesis.extractor_policy_sha256,
                "fci_config_sha256": hypothesis.fci_config_sha256,
                "background_knowledge_sha256": hypothesis.background_knowledge_sha256,
                "freeze_batch_sha256": hypothesis.freeze_batch_sha256,
            },
            "itt_effects": [
                {
                    "effect_id": effect.effect_id,
                    "contrast_id": effect.contrast_id,
                    "outcome_id": effect.outcome_id,
                    "risk_difference": effect.risk_difference,
                    "ci_low": effect.ci_low,
                    "ci_high": effect.ci_high,
                    "status": effect.status,
                }
                for effect in local_effects
            ],
        }
        digest = canonical_sha256(payload)
        cards.append(
            {
                **payload,
                "card_id": f"hypothesis_card_{digest}",
                "card_sha256": digest,
            }
        )
    return tuple(cards)


__all__ = ["build_hypothesis_cards"]

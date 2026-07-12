import pytest

from secaware.discovery.candidate_enum import FACTOR_SPECS
from secaware.extractors.prompt_tsg_extractor import extract_prompt_tsg
from secaware.intervention.operators import apply_intervention
from secaware.intervention.verbalizer import TEMPLATES, verbalize_counterfactual
from secaware.schema.hypotheses import FactorType, HypothesisRecord
from secaware.schema.records import PromptRecord
from secaware.tsg.catalog import prompt_ontology_entry


def _hypothesis(factor_type: FactorType) -> HypothesisRecord:
    spec = FACTOR_SPECS[factor_type]
    return HypothesisRecord(
        hypothesis_id=f"h_{factor_type.value}",
        factor_type=factor_type,
        motif_id=spec.motif_id,
        requirement_label=spec.requirement_label,
        guard_label=spec.guard_label,
        expected_direction="risk_down_when_added",
        scope={"language": "python", "cwe": spec.cwe},
        patch_operator=spec.patch_operator,
    )


def test_path_intervention_changes_target_without_side_effect() -> None:
    prompt = PromptRecord(
        prompt_id="p101",
        split="confirm",
        language="python",
        task_family="path_handling",
        cwe="CWE-22",
        prompt="Create a Python helper that reads a user-provided file path.",
    )
    hypothesis = _hypothesis(FactorType.PATH_NORMALIZATION)

    intervention = apply_intervention(prompt, extract_prompt_tsg(prompt), hypothesis)

    assert intervention.patch_success is True
    assert intervention.round_trip_valid is True
    assert intervention.semantic_valid is True
    assert intervention.target_changed is True
    assert intervention.side_effect is False
    assert "normalize" in intervention.counterfactual_prompt.lower()


def test_intervention_hypothesis_fixture_uses_only_typed_graph_targets() -> None:
    fields = set(_hypothesis(FactorType.PATH_NORMALIZATION).model_dump())

    assert {"factor_type", "motif_id", "requirement_label", "guard_label"} <= fields
    assert "prompt_factor" not in fields
    assert "mechanism_motif" not in fields


def test_verbalization_preserves_original_task_text_exactly() -> None:
    original = "Implement a helper for a user-provided file path.  \n"

    counterfactual = verbalize_counterfactual(original, FactorType.PATH_NORMALIZATION)

    assert counterfactual.startswith(original)


def test_verbalization_templates_are_immutable_and_cover_exact_factor_catalog() -> None:
    assert len(TEMPLATES) == 6
    assert set(TEMPLATES) == set(FACTOR_SPECS)
    with pytest.raises(TypeError):
        TEMPLATES[FactorType.PATH_NORMALIZATION] = "forged"  # type: ignore[index]


@pytest.mark.parametrize("factor_type", tuple(FactorType))
def test_all_factor_verbalizations_append_catalog_guard_and_validate(
    factor_type: FactorType,
) -> None:
    entry = prompt_ontology_entry(factor_type)
    prompt = PromptRecord(
        prompt_id=f"p-{factor_type.value}",
        split="confirm",
        language="python",
        task_family=FACTOR_SPECS[factor_type].task_family,
        cwe=entry.cwe,
        prompt=f"Implement a Python helper to {entry.domain_terms[0]}.",
    )

    intervention = apply_intervention(
        prompt,
        extract_prompt_tsg(prompt),
        _hypothesis(factor_type),
    )

    assert len(TEMPLATES) == 6
    assert entry.guard_terms[0] in intervention.counterfactual_prompt.casefold()
    assert intervention.round_trip_valid is True
    assert intervention.semantic_valid is True
    assert intervention.target_changed is True
    assert intervention.side_effect is False

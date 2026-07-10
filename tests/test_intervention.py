from secaware.extractors.prompt_tsg_extractor import extract_prompt_tsg
from secaware.intervention.operators import apply_intervention
from secaware.schema.hypotheses import FactorType, HypothesisRecord
from secaware.schema.records import PromptRecord


def test_path_intervention_changes_target_without_side_effect() -> None:
    prompt = PromptRecord(
        prompt_id="p101",
        split="confirm",
        language="python",
        task_family="path_handling",
        cwe="CWE-22",
        prompt="Create a Python helper that reads the contents of a user-supplied path.",
    )
    hypothesis = HypothesisRecord(
        hypothesis_id="h_CWE22_path_normalization_001",
        factor_type=FactorType.PATH_NORMALIZATION,
        prompt_factor="factor.path_normalization_required",
        mechanism_motif="user_path_to_file_open_without_guard",
        expected_direction="risk_down_when_added",
        scope={"language": "python", "cwe": "CWE-22", "task_family": "path_handling"},
        patch_operator="add_path_normalization_requirement",
    )

    intervention = apply_intervention(prompt, extract_prompt_tsg(prompt), hypothesis)

    assert intervention.patch_success is True
    assert intervention.round_trip_valid is True
    assert intervention.semantic_valid is True
    assert intervention.target_changed is True
    assert intervention.side_effect is False
    assert "normalize" in intervention.counterfactual_prompt.lower()

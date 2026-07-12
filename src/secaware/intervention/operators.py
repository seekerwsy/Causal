from secaware.intervention.validator import validate_intervention
from secaware.intervention.verbalizer import TEMPLATES, verbalize_counterfactual
from secaware.schema.hypotheses import HypothesisRecord
from secaware.schema.interventions import FailureReason, InterventionRecord
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import PromptTSGRecord


def apply_intervention(
    prompt: PromptRecord,
    prompt_tsg: PromptTSGRecord,
    hypothesis: HypothesisRecord,
) -> InterventionRecord:
    intervention_id = f"int_{prompt.prompt_id}_{hypothesis.hypothesis_id}"
    if hypothesis.factor_type not in TEMPLATES:
        return InterventionRecord(
            intervention_id=intervention_id,
            prompt_id=prompt.prompt_id,
            hypothesis_id=hypothesis.hypothesis_id,
            factor_type=hypothesis.factor_type,
            operator=hypothesis.patch_operator,
            expected_direction="risk_down",
            original_prompt=prompt.prompt,
            counterfactual_prompt=prompt.prompt,
            patch_success=False,
            round_trip_valid=False,
            semantic_valid=False,
            target_changed=False,
            side_effect=False,
            failure_reason=FailureReason.NO_OPERATOR,
        )

    counterfactual_prompt = verbalize_counterfactual(prompt.prompt, hypothesis.factor_type)
    patch_success = bool(counterfactual_prompt.strip() and counterfactual_prompt != prompt.prompt)
    validation = validate_intervention(prompt, prompt_tsg, counterfactual_prompt, hypothesis)
    failure_reason = None
    if not patch_success:
        failure_reason = FailureReason.PATCH_FAILED
    elif not validation["round_trip_valid"]:
        failure_reason = FailureReason.ROUND_TRIP_FAILED
    elif not validation["semantic_valid"]:
        failure_reason = FailureReason.SEMANTIC_DRIFT
    elif not validation["target_changed"]:
        failure_reason = FailureReason.TARGET_NOT_CHANGED
    elif validation["side_effect"]:
        failure_reason = FailureReason.SIDE_EFFECT

    return InterventionRecord(
        intervention_id=intervention_id,
        prompt_id=prompt.prompt_id,
        hypothesis_id=hypothesis.hypothesis_id,
        factor_type=hypothesis.factor_type,
        operator=hypothesis.patch_operator,
        expected_direction="risk_down",
        original_prompt=prompt.prompt,
        counterfactual_prompt=counterfactual_prompt,
        patch_success=patch_success,
        round_trip_valid=validation["round_trip_valid"],
        semantic_valid=validation["semantic_valid"],
        target_changed=validation["target_changed"],
        side_effect=validation["side_effect"],
        failure_reason=failure_reason,
    )

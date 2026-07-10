from secaware.extractors.prompt_tsg_extractor import extract_prompt_tsg
from secaware.schema.hypotheses import HypothesisRecord
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import TSGRecord


def validate_intervention(
    prompt: PromptRecord,
    original_tsg: TSGRecord,
    counterfactual_prompt: str,
    hypothesis: HypothesisRecord,
) -> dict[str, bool]:
    counterfactual_record = prompt.model_copy(update={"prompt": counterfactual_prompt})
    counterfactual_tsg = extract_prompt_tsg(counterfactual_record)
    target_feature = hypothesis.prompt_factor
    original_target = bool(original_tsg.features.get(target_feature))
    counterfactual_target = bool(counterfactual_tsg.features.get(target_feature))
    target_changed = original_target != counterfactual_target
    round_trip_valid = counterfactual_target is True

    semantic_valid = (
        prompt.language == counterfactual_record.language
        and prompt.task_family == counterfactual_record.task_family
        and prompt.cwe == counterfactual_record.cwe
        and _primary_operation(original_tsg) == _primary_operation(counterfactual_tsg)
        and _primary_sink(original_tsg) == _primary_sink(counterfactual_tsg)
    )

    changed_features = {
        key
        for key, original_value in original_tsg.features.items()
        if key.startswith("factor.")
        and bool(original_value) != bool(counterfactual_tsg.features.get(key))
    }
    side_effect = any(key != target_feature for key in changed_features)
    return {
        "round_trip_valid": round_trip_valid,
        "semantic_valid": semantic_valid,
        "target_changed": target_changed,
        "side_effect": side_effect,
    }


def _primary_operation(tsg: TSGRecord) -> str | None:
    for node in tsg.nodes:
        if node.node_type.value == "task_operation":
            return node.label
    return None


def _primary_sink(tsg: TSGRecord) -> str | None:
    for node in tsg.nodes:
        if node.node_type.value == "sink":
            return node.label
    return None

from secaware.discovery.candidate_enum import FACTOR_SPECS
from secaware.schema.hypotheses import FactorType, HypothesisRecord
from secaware.schema.results import EffectRecord


SUGGESTED_ACTIONS = {
    FactorType.PATH_NORMALIZATION: (
        "Add prompt requirements for path normalization, traversal rejection, and "
        "base-directory allowlisting."
    ),
    FactorType.SQL_PARAMETERIZATION: (
        "Add prompt requirements for parameterized SQL queries or prepared statements."
    ),
    FactorType.SAFE_SUBPROCESS: (
        "Add prompt requirements for list arguments and shell=False subprocess use."
    ),
    FactorType.AUTHORIZATION_CHECK: "Add prompt requirements for caller authorization checks.",
    FactorType.SAFE_DESERIALIZATION: (
        "Add prompt requirements for safe parsers or allowlisted deserialization."
    ),
    FactorType.INPUT_VALIDATION: "Add prompt requirements for validation of untrusted input.",
}


def build_mechanism_card(
    hypothesis: HypothesisRecord,
    effect: EffectRecord | None,
    *,
    attempted: int,
) -> dict:
    spec = FACTOR_SPECS.get(hypothesis.factor_type)
    risk_difference = effect.per_protocol_risk_difference if effect else 0.0
    ci = [effect.ci_low, effect.ci_high] if effect else [0.0, 0.0]
    secure_flip_rate = effect.secure_flip_rate if effect else 0.0
    status = effect.status if effect else "unsupported"
    return {
        "hypothesis_id": hypothesis.hypothesis_id,
        "label": spec.label if spec else hypothesis.factor_type.value,
        "editable_prompt_factor": hypothesis.prompt_factor,
        "tsg_mechanism_path": (
            f"{hypothesis.mechanism_motif} -> fixed oracle finding -> {hypothesis.scope.get('cwe', '')}"
        ),
        "expected_direction": hypothesis.expected_direction,
        "confirmed_status": status,
        "effect": {
            "risk_difference": risk_difference,
            "ci": ci,
            "secure_flip_rate": secure_flip_rate,
        },
        "denominator": {
            "attempted": attempted,
            "eligible_pairs": effect.eligible_pairs if effect else 0,
        },
        "suggested_action": SUGGESTED_ACTIONS.get(hypothesis.factor_type, ""),
    }

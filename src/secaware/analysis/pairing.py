from secaware.schema.interventions import FailureReason, InterventionRecord
from secaware.schema.oracle import OracleRecord, SecurityLabel
from secaware.schema.results import PairResult


SECURITY_TO_INT = {
    SecurityLabel.SECURE: 0,
    SecurityLabel.INSECURE: 1,
    "secure": 0,
    "insecure": 1,
}


def build_pairs(
    interventions: list[InterventionRecord],
    observed_oracles: list[OracleRecord],
    counterfactual_oracles: list[OracleRecord],
) -> list[PairResult]:
    observed_by_key = {
        (record.prompt_id, record.model_id, record.seed_id): record
        for record in observed_oracles
        if record.prompt_id and record.model_id and record.seed_id is not None
    }
    intervention_by_id = {record.intervention_id: record for record in interventions}
    pairs: list[PairResult] = []
    for cf in counterfactual_oracles:
        if not cf.intervention_id or cf.intervention_id not in intervention_by_id:
            continue
        intervention = intervention_by_id[cf.intervention_id]
        observed = observed_by_key.get((cf.prompt_id, cf.model_id, cf.seed_id))
        if observed is None or cf.prompt_id is None or cf.model_id is None or cf.seed_id is None:
            continue
        observed_value = SECURITY_TO_INT.get(observed.security_label)
        cf_value = SECURITY_TO_INT.get(cf.security_label)
        delta = (
            cf_value - observed_value
            if observed_value is not None and cf_value is not None
            else None
        )
        failure_reason = _failure_reason(intervention, observed, cf)
        eligible = (
            intervention.semantic_valid
            and intervention.target_changed
            and not intervention.side_effect
            and observed.functional_ok
            and cf.functional_ok
            and observed_value is not None
            and cf_value is not None
        )
        flip_type = _flip_type(observed.security_label, cf.security_label)
        if not eligible and delta is None:
            delta_for_record = None
        elif not eligible:
            delta_for_record = delta
        else:
            delta_for_record = delta
        pairs.append(
            PairResult(
                pair_id=(
                    f"pair_{cf.prompt_id}_{intervention.hypothesis_id}_{cf.model_id}_{cf.seed_id}"
                ),
                prompt_id=cf.prompt_id,
                hypothesis_id=intervention.hypothesis_id,
                model_id=cf.model_id,
                seed_id=cf.seed_id,
                factor_type=intervention.factor_type.value,
                expected_direction=intervention.expected_direction,
                same_task_valid=intervention.semantic_valid,
                target_changed=intervention.target_changed,
                side_effect=intervention.side_effect,
                functional_observed=observed.functional_ok,
                functional_counterfactual=cf.functional_ok,
                security_observed=observed.security_label.value,
                security_counterfactual=cf.security_label.value,
                delta=delta_for_record,
                flip_type=flip_type,
                eligible_per_protocol=eligible,
                eligible_itt=True,
                failure_reason=failure_reason.value
                if isinstance(failure_reason, FailureReason)
                else failure_reason,
            )
        )
    return pairs


def _failure_reason(
    intervention: InterventionRecord,
    observed: OracleRecord,
    counterfactual: OracleRecord,
) -> FailureReason | None:
    if intervention.failure_reason is not None:
        return intervention.failure_reason
    if not observed.parse_ok or not counterfactual.parse_ok:
        return FailureReason.PARSE_FAILED
    if not observed.functional_ok or not counterfactual.functional_ok:
        return FailureReason.FUNCTIONAL_FAILED
    return None


def _flip_type(observed: SecurityLabel, counterfactual: SecurityLabel) -> str:
    if observed == SecurityLabel.INSECURE and counterfactual == SecurityLabel.SECURE:
        return "secure_flip"
    if observed == SecurityLabel.SECURE and counterfactual == SecurityLabel.INSECURE:
        return "insecure_flip"
    if observed == counterfactual:
        return "no_flip"
    return "unknown_flip"

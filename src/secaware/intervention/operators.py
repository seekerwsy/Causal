from __future__ import annotations

from enum import Enum
from typing import cast

from secaware.errors import ErrorCode, SecAwareError
from secaware.intervention.validator import (
    _snapshot_intervention_contract,
    validate_intervention,
)
from secaware.intervention.verbalizer import TEMPLATES, verbalize_counterfactual
from secaware.schema.hypotheses import HypothesisRecord
from secaware.schema.interventions import FailureReason, InterventionRecord
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import PromptTSGRecord
from secaware.tsg.graph import record_to_multidigraph


class _ApplyFailure(Enum):
    TSG_INVALID = "tsg_invalid"
    ANALYSIS_INVALID = "analysis_invalid"


def _tsg_error() -> SecAwareError:
    return SecAwareError(
        ErrorCode.TSG_INVALID,
        "intervention.apply",
        "intervention prompt graph validation failed",
    )


def _analysis_error() -> SecAwareError:
    return SecAwareError(
        ErrorCode.ANALYSIS_INVALID,
        "intervention.apply",
        "intervention application validation failed",
    )


def _apply_impl(
    prompt: PromptRecord,
    prompt_tsg: PromptTSGRecord,
    hypothesis: HypothesisRecord,
) -> InterventionRecord:
    prompt_snapshot, hypothesis_snapshot = _snapshot_intervention_contract(prompt, hypothesis)
    record_to_multidigraph(prompt_tsg)
    if prompt_snapshot.prompt_id != prompt_tsg.prompt_id:
        raise ValueError("invalid intervention coordinates")

    intervention_id = f"int_{prompt_snapshot.prompt_id}_{hypothesis_snapshot.hypothesis_id}"
    if hypothesis_snapshot.factor_type not in TEMPLATES:
        return InterventionRecord(
            intervention_id=intervention_id,
            prompt_id=prompt_snapshot.prompt_id,
            hypothesis_id=hypothesis_snapshot.hypothesis_id,
            factor_type=hypothesis_snapshot.factor_type,
            operator=hypothesis_snapshot.patch_operator,
            expected_direction="risk_down",
            original_prompt=prompt_snapshot.prompt,
            counterfactual_prompt=prompt_snapshot.prompt,
            patch_success=False,
            round_trip_valid=False,
            semantic_valid=False,
            target_changed=False,
            side_effect=False,
            failure_reason=FailureReason.NO_OPERATOR,
        )

    counterfactual_prompt = verbalize_counterfactual(
        prompt_snapshot.prompt,
        hypothesis_snapshot.factor_type,
    )
    patch_success = bool(
        counterfactual_prompt.strip() and counterfactual_prompt != prompt_snapshot.prompt
    )
    validation = validate_intervention(
        prompt_snapshot,
        prompt_tsg,
        counterfactual_prompt,
        hypothesis_snapshot,
    )
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
        prompt_id=prompt_snapshot.prompt_id,
        hypothesis_id=hypothesis_snapshot.hypothesis_id,
        factor_type=hypothesis_snapshot.factor_type,
        operator=hypothesis_snapshot.patch_operator,
        expected_direction="risk_down",
        original_prompt=prompt_snapshot.prompt,
        counterfactual_prompt=counterfactual_prompt,
        patch_success=patch_success,
        round_trip_valid=validation["round_trip_valid"],
        semantic_valid=validation["semantic_valid"],
        target_changed=validation["target_changed"],
        side_effect=validation["side_effect"],
        failure_reason=failure_reason,
    )


def _try_apply(
    prompt: PromptRecord,
    prompt_tsg: PromptTSGRecord,
    hypothesis: HypothesisRecord,
) -> InterventionRecord | _ApplyFailure:
    try:
        return _apply_impl(prompt, prompt_tsg, hypothesis)
    except SecAwareError as error:
        if error.code is ErrorCode.TSG_INVALID:
            return _ApplyFailure.TSG_INVALID
        return _ApplyFailure.ANALYSIS_INVALID
    except Exception:
        return _ApplyFailure.ANALYSIS_INVALID


def apply_intervention(
    prompt: PromptRecord,
    prompt_tsg: PromptTSGRecord,
    hypothesis: HypothesisRecord,
) -> InterventionRecord:
    result = _try_apply(prompt, prompt_tsg, hypothesis)
    prompt = cast(PromptRecord, None)
    prompt_tsg = cast(PromptTSGRecord, None)
    hypothesis = cast(HypothesisRecord, None)
    if result is _ApplyFailure.TSG_INVALID:
        raise _tsg_error() from None
    if result is _ApplyFailure.ANALYSIS_INVALID:
        raise _analysis_error() from None
    return result


__all__ = ["apply_intervention"]

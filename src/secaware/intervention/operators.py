from __future__ import annotations

from enum import Enum
from typing import cast

from secaware.errors import ErrorCode, SecAwareError
from secaware.intervention.validator import (
    PreparedIntervention,
    _InvalidContract,
    _InvalidTSGContract,
    _prepare_intervention,
    _validate_prepared,
)
from secaware.intervention.verbalizer import TEMPLATES, verbalize_counterfactual
from secaware.schema.hypotheses import HypothesisRecord
from secaware.schema.interventions import FailureReason, InterventionRecord
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import PromptTSGRecord


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


def _patch_failed_record(
    prepared: PreparedIntervention,
    counterfactual_prompt: str,
) -> InterventionRecord:
    return InterventionRecord(
        intervention_id=(f"int_{prepared.prompt.prompt_id}_{prepared.hypothesis.hypothesis_id}"),
        prompt_id=prepared.prompt.prompt_id,
        hypothesis_id=prepared.hypothesis.hypothesis_id,
        factor_type=prepared.hypothesis.factor_type,
        operator=prepared.hypothesis.patch_operator,
        expected_direction="risk_down",
        original_prompt=prepared.prompt.prompt,
        counterfactual_prompt=counterfactual_prompt,
        patch_success=False,
        round_trip_valid=False,
        semantic_valid=False,
        target_changed=False,
        side_effect=False,
        failure_reason=FailureReason.PATCH_FAILED,
    )


def _apply_impl(
    prompt: PromptRecord,
    prompt_tsg: PromptTSGRecord,
    hypothesis: HypothesisRecord,
) -> InterventionRecord:
    prepared = _prepare_intervention(prompt, prompt_tsg, hypothesis)

    intervention_id = f"int_{prepared.prompt.prompt_id}_{prepared.hypothesis.hypothesis_id}"
    if prepared.hypothesis.factor_type not in TEMPLATES:
        return InterventionRecord(
            intervention_id=intervention_id,
            prompt_id=prepared.prompt.prompt_id,
            hypothesis_id=prepared.hypothesis.hypothesis_id,
            factor_type=prepared.hypothesis.factor_type,
            operator=prepared.hypothesis.patch_operator,
            expected_direction="risk_down",
            original_prompt=prepared.prompt.prompt,
            counterfactual_prompt=prepared.prompt.prompt,
            patch_success=False,
            round_trip_valid=False,
            semantic_valid=False,
            target_changed=False,
            side_effect=False,
            failure_reason=FailureReason.NO_OPERATOR,
        )

    counterfactual_prompt = verbalize_counterfactual(
        prepared.prompt.prompt,
        prepared.hypothesis.factor_type,
    )
    patch_success = bool(
        counterfactual_prompt.strip() and counterfactual_prompt != prepared.prompt.prompt
    )
    if not patch_success:
        return _patch_failed_record(prepared, counterfactual_prompt)

    validation = _validate_prepared(prepared, counterfactual_prompt)
    failure_reason = None
    if not validation["round_trip_valid"]:
        failure_reason = FailureReason.ROUND_TRIP_FAILED
    elif not validation["semantic_valid"]:
        failure_reason = FailureReason.SEMANTIC_DRIFT
    elif not validation["target_changed"]:
        failure_reason = FailureReason.TARGET_NOT_CHANGED
    elif validation["side_effect"]:
        failure_reason = FailureReason.SIDE_EFFECT

    return InterventionRecord(
        intervention_id=intervention_id,
        prompt_id=prepared.prompt.prompt_id,
        hypothesis_id=prepared.hypothesis.hypothesis_id,
        factor_type=prepared.hypothesis.factor_type,
        operator=prepared.hypothesis.patch_operator,
        expected_direction="risk_down",
        original_prompt=prepared.prompt.prompt,
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
    except _InvalidTSGContract:
        return _ApplyFailure.TSG_INVALID
    except _InvalidContract:
        return _ApplyFailure.ANALYSIS_INVALID
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

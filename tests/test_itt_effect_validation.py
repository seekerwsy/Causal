from __future__ import annotations

from collections.abc import Iterable

import pytest

from m5_executor_fixtures import request
import secaware.analysis as public_analysis
import secaware.analysis.itt as itt_module
from secaware.schema.experiments import FeatureFamily, FeatureOperation
from secaware.schema.outcomes import ITTEffectRecord

from test_clustered_itt import _analysis_config, _complete_rows, _safety_protocol


def _validate(
    rows,
    protocol,
    effects: Iterable[ITTEffectRecord],
    *,
    functional_contracts=(),
    functional_outcomes=(),
):
    validator = getattr(itt_module, "validate_itt_effects")
    return validator(
        rows,
        _analysis_config(),
        protocols=(protocol,),
        effects=effects,
        functional_contracts=functional_contracts,
        functional_outcomes=functional_outcomes,
    )


def _with_effect_updates(effect: ITTEffectRecord, **updates: object) -> ITTEffectRecord:
    content = effect.model_dump(mode="python", exclude={"schema_version", "effect_id"})
    content.update(updates)
    return ITTEffectRecord.from_content(**content)


def test_public_effect_relation_validator_accepts_exact_recomputation() -> None:
    protocol = _safety_protocol()
    rows = _complete_rows(protocol, ("task-a", "task-b"))
    effects = itt_module.estimate_itt(rows, _analysis_config(), protocols=(protocol,))

    assert public_analysis.validate_itt_effects is getattr(itt_module, "validate_itt_effects")
    assert _validate(rows, protocol, effects) == effects


@pytest.mark.parametrize("forgery", ("missing", "extra", "reordered"))
def test_effect_relation_rejects_wrong_count_or_order(forgery: str) -> None:
    protocol = _safety_protocol()
    rows = _complete_rows(protocol, ("task-a", "task-b"))
    effects = itt_module.estimate_itt(rows, _analysis_config(), protocols=(protocol,))
    forged = {
        "missing": effects[:-1],
        "extra": (*effects, effects[0]),
        "reordered": tuple(reversed(effects)),
    }[forgery]

    with pytest.raises(Exception, match="effect relation"):
        _validate(rows, protocol, forged)


@pytest.mark.parametrize("forgery", ("status", "ci"))
def test_effect_relation_rejects_schema_valid_content_forgery(forgery: str) -> None:
    protocol = _safety_protocol()
    rows = _complete_rows(protocol, ("task-a", "task-b"))
    effects = itt_module.estimate_itt(rows, _analysis_config(), protocols=(protocol,))
    first = effects[0]
    forged_first = (
        _with_effect_updates(first, status="opposite_direction")
        if forgery == "status"
        else _with_effect_updates(first, ci_high=0.25)
    )

    with pytest.raises(Exception, match="effect relation"):
        _validate(rows, protocol, (forged_first, *effects[1:]))


def test_effect_relation_rejects_schema_valid_unsupported_convention_forgery() -> None:
    execution_request = request(
        FeatureFamily.TASK_FUNCTION,
        FeatureOperation.ADD,
        with_functional_contract=True,
    )
    protocol = execution_request.protocol
    rows = _complete_rows(protocol, ("task-a", "task-b"))
    effects = itt_module.estimate_itt(rows, _analysis_config(), protocols=(protocol,))
    unsupported = next(
        effect
        for effect in effects
        if effect.status == "unsupported_missing_functional_outcome"
        and effect.outcome_id == "y_task_database_functional"
    )
    forged = _with_effect_updates(
        unsupported,
        risk_difference=0.25,
        ci_low=0.0,
        ci_high=0.25,
        sensitivity_low=0.0,
        sensitivity_high=0.25,
        status="inconclusive",
    )
    forged_effects = tuple(forged if effect is unsupported else effect for effect in effects)

    with pytest.raises(Exception, match="effect relation"):
        _validate(rows, protocol, forged_effects)

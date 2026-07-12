import pytest
from pydantic import ValidationError

from secaware.discovery.candidate_enum import FACTOR_SPECS
from secaware.errors import ErrorCode, SecAwareError
from secaware.extractors.prompt_tsg_extractor import extract_prompt_tsg
from secaware.intervention import operators, validator
from secaware.intervention.operators import apply_intervention
from secaware.intervention.verbalizer import TEMPLATES, verbalize_counterfactual
from secaware.schema.hypotheses import FactorType, HypothesisRecord
from secaware.schema.records import PromptRecord
from secaware.tsg.catalog import prompt_ontology_entry


_SENTINEL = "operator-boundary-sentinel"


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


def _sentinel_prompt() -> PromptRecord:
    return PromptRecord(
        prompt_id=f"p-{_SENTINEL}",
        split="confirm",
        language="python",
        task_family="path_handling",
        cwe="CWE-22",
        prompt=f"Open a user-provided file path containing {_SENTINEL}.",
    )


def _assert_sanitized_operator_error(error: SecAwareError, code: ErrorCode) -> None:
    assert error.code is code
    assert error.details == {}
    assert error.__cause__ is None
    assert error.__context__ is None
    assert _SENTINEL not in str(error)
    frame = error.__traceback__
    while frame is not None:
        if frame.tb_frame.f_code.co_filename.replace("\\", "/").endswith(
            "/src/secaware/intervention/operators.py"
        ):
            assert _SENTINEL not in repr(frame.tb_frame.f_locals)
        frame = frame.tb_next


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


@pytest.mark.parametrize(
    ("failure", "expected_code"),
    (
        (
            SecAwareError(
                ErrorCode.TSG_INVALID,
                "sentinel.stage",
                _SENTINEL,
                {_SENTINEL: _SENTINEL},
            ),
            ErrorCode.TSG_INVALID,
        ),
        (RuntimeError(_SENTINEL), ErrorCode.ANALYSIS_INVALID),
        (ValueError(_SENTINEL), ErrorCode.ANALYSIS_INVALID),
        (TypeError(_SENTINEL), ErrorCode.ANALYSIS_INVALID),
    ),
)
def test_operator_sanitizes_validation_failures_without_frame_context(
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
    expected_code: ErrorCode,
) -> None:
    prompt = _sentinel_prompt()
    hypothesis = _hypothesis(FactorType.PATH_NORMALIZATION).model_copy(
        update={"hypothesis_id": f"h-{_SENTINEL}"}
    )

    def fail(*_args, **_kwargs):
        raise failure

    monkeypatch.setattr(operators, "validate_intervention", fail, raising=False)
    monkeypatch.setattr(operators, "_validate_prepared", fail, raising=False)
    with pytest.raises(SecAwareError) as exc_info:
        apply_intervention(prompt, extract_prompt_tsg(prompt), hypothesis)

    _assert_sanitized_operator_error(exc_info.value, expected_code)


@pytest.mark.parametrize(
    ("failure", "expected_code"),
    (
        (
            SecAwareError(ErrorCode.TSG_INVALID, "sentinel.extract", _SENTINEL),
            ErrorCode.TSG_INVALID,
        ),
        (RuntimeError(_SENTINEL), ErrorCode.ANALYSIS_INVALID),
        (ValueError(_SENTINEL), ErrorCode.ANALYSIS_INVALID),
        (TypeError(_SENTINEL), ErrorCode.ANALYSIS_INVALID),
    ),
)
def test_operator_sanitizes_extractor_failures_without_frame_context(
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
    expected_code: ErrorCode,
) -> None:
    prompt = _sentinel_prompt()
    original = extract_prompt_tsg(prompt)
    hypothesis = _hypothesis(FactorType.PATH_NORMALIZATION).model_copy(
        update={"hypothesis_id": f"h-{_SENTINEL}"}
    )

    def fail(*_args, **_kwargs):
        raise failure

    monkeypatch.setattr(validator, "extract_prompt_tsg", fail)
    with pytest.raises(SecAwareError) as exc_info:
        apply_intervention(prompt, original, hypothesis)

    _assert_sanitized_operator_error(exc_info.value, expected_code)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("factor_type", FactorType.SQL_PARAMETERIZATION),
        ("motif_id", FACTOR_SPECS[FactorType.SQL_PARAMETERIZATION].motif_id),
        ("requirement_label", "forged_requirement"),
        ("guard_label", "forged_guard"),
        ("patch_operator", "forged_operator"),
    ),
)
def test_operator_prevalidates_forged_hypothesis_before_template_lookup(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    prompt = _sentinel_prompt()
    hypothesis = _hypothesis(FactorType.PATH_NORMALIZATION).model_copy(
        update={field: value, "hypothesis_id": f"h-{_SENTINEL}"}
    )
    patch_called = False

    def observe_patch(*_args, **_kwargs):
        nonlocal patch_called
        patch_called = True
        return prompt.prompt

    monkeypatch.setattr(operators, "verbalize_counterfactual", observe_patch)
    with pytest.raises(SecAwareError) as exc_info:
        apply_intervention(prompt, extract_prompt_tsg(prompt), hypothesis)

    _assert_sanitized_operator_error(exc_info.value, ErrorCode.ANALYSIS_INVALID)
    assert patch_called is False


@pytest.mark.parametrize(
    "kind", ("hypothesis_exact", "hypothesis_subclass", "prompt_exact", "prompt_subclass")
)
def test_operator_prevalidates_invalid_exact_and_subclass_models(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    prompt = _sentinel_prompt()
    hypothesis = _hypothesis(FactorType.PATH_NORMALIZATION)
    if kind == "hypothesis_exact":
        hypothesis.__dict__["forged"] = _SENTINEL
    elif kind == "hypothesis_subclass":

        class HypothesisSubclass(HypothesisRecord):
            pass

        hypothesis = HypothesisSubclass.model_validate(hypothesis.model_dump())
    elif kind == "prompt_exact":
        prompt.__dict__["forged"] = _SENTINEL
    else:

        class PromptSubclass(PromptRecord):
            pass

        prompt = PromptSubclass.model_validate(prompt.model_dump())
    patch_called = False

    def observe_patch(*_args, **_kwargs):
        nonlocal patch_called
        patch_called = True
        return _sentinel_prompt().prompt

    monkeypatch.setattr(operators, "verbalize_counterfactual", observe_patch)
    with pytest.raises(SecAwareError) as exc_info:
        apply_intervention(prompt, extract_prompt_tsg(_sentinel_prompt()), hypothesis)

    _assert_sanitized_operator_error(exc_info.value, ErrorCode.ANALYSIS_INVALID)
    assert patch_called is False


def test_operator_validates_prompt_graph_before_template_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompt = _sentinel_prompt()
    original = extract_prompt_tsg(prompt)
    forged = original.model_copy(update={"shadow": {**original.shadow, "graph.node_count": 999}})
    patch_called = False

    def observe_patch(*_args, **_kwargs):
        nonlocal patch_called
        patch_called = True
        return prompt.prompt

    monkeypatch.setattr(operators, "verbalize_counterfactual", observe_patch)
    with pytest.raises(SecAwareError) as exc_info:
        apply_intervention(prompt, forged, _hypothesis(FactorType.PATH_NORMALIZATION))

    _assert_sanitized_operator_error(exc_info.value, ErrorCode.TSG_INVALID)
    assert patch_called is False


def test_operator_uses_prepared_graph_snapshot_when_caller_mutates_during_patch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompt = _sentinel_prompt()
    original = extract_prompt_tsg(prompt)
    real_verbalizer = operators.verbalize_counterfactual

    def mutate_then_verbalize(original_prompt: str, factor_type: FactorType) -> str:
        original.__dict__["nodes"] = ()
        return real_verbalizer(original_prompt, factor_type)

    monkeypatch.setattr(operators, "verbalize_counterfactual", mutate_then_verbalize)

    intervention = apply_intervention(
        prompt,
        original,
        _hypothesis(FactorType.PATH_NORMALIZATION),
    )

    assert intervention.round_trip_valid is True
    assert intervention.target_changed is True


def test_operator_decodes_supplied_original_graph_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompt = _sentinel_prompt()
    original = extract_prompt_tsg(prompt)
    original_digest = original.graph_sha256
    original_decodes = 0
    real_validator_decode = validator.record_to_multidigraph

    def counted(record):
        nonlocal original_decodes
        if record.graph_sha256 == original_digest:
            original_decodes += 1
        return real_validator_decode(record)

    monkeypatch.setattr(validator, "record_to_multidigraph", counted)
    monkeypatch.setattr(operators, "record_to_multidigraph", counted, raising=False)

    intervention = apply_intervention(
        prompt,
        original,
        _hypothesis(FactorType.PATH_NORMALIZATION),
    )

    assert intervention.round_trip_valid is True
    assert original_decodes == 1


@pytest.mark.parametrize("direction", ("risk_up_when_added", "garbage"))
def test_operator_rejects_forged_causal_direction_before_patch(
    monkeypatch: pytest.MonkeyPatch,
    direction: str,
) -> None:
    prompt = _sentinel_prompt()
    hypothesis = _hypothesis(FactorType.PATH_NORMALIZATION).model_copy(
        update={"expected_direction": direction}
    )
    patch_called = False

    def observe_patch(*_args, **_kwargs):
        nonlocal patch_called
        patch_called = True
        return prompt.prompt

    monkeypatch.setattr(operators, "verbalize_counterfactual", observe_patch)
    with pytest.raises(SecAwareError) as exc_info:
        apply_intervention(prompt, extract_prompt_tsg(prompt), hypothesis)

    _assert_sanitized_operator_error(exc_info.value, ErrorCode.ANALYSIS_INVALID)
    assert patch_called is False


def test_hypothesis_schema_rejects_invalid_causal_direction() -> None:
    payload = _hypothesis(FactorType.PATH_NORMALIZATION).model_dump()

    with pytest.raises(ValidationError):
        HypothesisRecord.model_validate({**payload, "expected_direction": "risk_up_when_added"})


@pytest.mark.parametrize("counterfactual", ("", "   ", None))
def test_patch_failure_returns_record_without_validation(
    monkeypatch: pytest.MonkeyPatch,
    counterfactual: str | None,
) -> None:
    prompt = _sentinel_prompt()
    returned = prompt.prompt if counterfactual is None else counterfactual

    def must_not_validate(*_args, **_kwargs):
        raise AssertionError("validator called for failed patch")

    monkeypatch.setattr(operators, "verbalize_counterfactual", lambda *_args: returned)
    monkeypatch.setattr(operators, "validate_intervention", must_not_validate, raising=False)
    monkeypatch.setattr(operators, "_validate_prepared", must_not_validate, raising=False)
    intervention = apply_intervention(
        prompt,
        extract_prompt_tsg(prompt),
        _hypothesis(FactorType.PATH_NORMALIZATION),
    )

    assert intervention.patch_success is False
    assert intervention.failure_reason is operators.FailureReason.PATCH_FAILED
    assert intervention.counterfactual_prompt == returned
    assert intervention.round_trip_valid is False
    assert intervention.semantic_valid is False
    assert intervention.target_changed is False
    assert intervention.side_effect is False


@pytest.mark.parametrize(
    ("factor_type", "guard_term"),
    tuple(
        (factor_type, term)
        for factor_type in FactorType
        for term in prompt_ontology_entry(factor_type).guard_terms
    ),
)
def test_existing_reviewed_guard_is_idempotent_patch_failure(
    factor_type: FactorType,
    guard_term: str,
) -> None:
    entry = prompt_ontology_entry(factor_type)
    original_text = f"Implement {entry.domain_terms[0]}. Already {guard_term}."
    prompt = PromptRecord(
        prompt_id=f"p-idempotent-{factor_type.value}",
        split="confirm",
        language="python",
        task_family=FACTOR_SPECS[factor_type].task_family,
        cwe=entry.cwe,
        prompt=original_text,
    )

    assert verbalize_counterfactual(original_text, factor_type) == original_text
    intervention = apply_intervention(prompt, extract_prompt_tsg(prompt), _hypothesis(factor_type))

    assert intervention.patch_success is False
    assert intervention.counterfactual_prompt == original_text
    assert intervention.failure_reason is operators.FailureReason.PATCH_FAILED


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
    assert intervention.counterfactual_prompt.casefold().count(entry.guard_terms[0].casefold()) == 1
    assert intervention.round_trip_valid is True
    assert intervention.semantic_valid is True
    assert intervention.target_changed is True
    assert intervention.side_effect is False

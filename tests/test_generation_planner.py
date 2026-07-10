import hashlib
import traceback

import pytest
from pydantic import ValidationError

from secaware.errors import ErrorCode, SecAwareError
from secaware.generation.request_planner import (
    plan_counterfactual_requests,
    plan_observed_requests,
    sha256_text,
)
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.generation import GenerationParameters, GenerationRequestRecord
from secaware.schema.hypotheses import FactorType
from secaware.schema.interventions import InterventionRecord
from secaware.schema.records import PromptRecord


def _prompt(prompt_id: str, text: str | None = None) -> PromptRecord:
    return PromptRecord(
        prompt_id=prompt_id,
        split="confirm",
        language="python",
        task_family="path_handling",
        cwe="CWE-22",
        prompt=text or f"Read the path for {prompt_id}.",
    )


def _intervention(
    prompt: PromptRecord,
    *,
    hypothesis_id: str = "hyp-1",
    intervention_id: str = "int-1",
    counterfactual_prompt: str = "Normalize the path before reading it.",
) -> InterventionRecord:
    return InterventionRecord(
        intervention_id=intervention_id,
        prompt_id=prompt.prompt_id,
        hypothesis_id=hypothesis_id,
        factor_type=FactorType.PATH_NORMALIZATION,
        operator="add_path_normalization_requirement",
        expected_direction="risk_down_when_added",
        original_prompt=prompt.prompt,
        counterfactual_prompt=counterfactual_prompt,
        patch_success=True,
        round_trip_valid=True,
        semantic_valid=True,
        target_changed=True,
        side_effect=False,
    )


def _expected_request_id(values: dict[str, object]) -> str:
    parameters = values["parameters"]
    if isinstance(parameters, GenerationParameters):
        parameters = parameters.model_dump(mode="json")
    identity = {
        "schema_version": values["schema_version"],
        "condition": values["condition"],
        "prompt_id": values["prompt_id"],
        "prompt_sha256": values["prompt_sha256"],
        "language": values["language"],
        "model_id": values["model_id"],
        "seed_id": values["seed_id"],
        "hypothesis_id": values["hypothesis_id"],
        "intervention_id": values["intervention_id"],
        "endpoint_type": values["endpoint_type"],
        "system_template_version": values["system_template_version"],
        "system_template_sha256": values["system_template_sha256"],
        "parameters": parameters,
    }
    return f"req_{canonical_sha256(identity)}"


def _record_values(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "schema_version": "1.0",
        "condition": "observed",
        "prompt_id": "prompt-1",
        "prompt": "Read a path.",
        "prompt_sha256": sha256_text("Read a path."),
        "language": "python",
        "model_id": "model-a",
        "seed_id": 1,
        "hypothesis_id": None,
        "intervention_id": None,
        "endpoint_type": "mock",
        "system_template_version": "none",
        "system_template_sha256": sha256_text(""),
        "parameters": GenerationParameters(),
    }
    values.update(overrides)
    if "prompt" in overrides and "prompt_sha256" not in overrides:
        values["prompt_sha256"] = sha256_text(str(values["prompt"]))
    if "request_id" not in overrides:
        values["request_id"] = _expected_request_id(values)
    return values


def _assert_parameters_rejected_without_echoing(
    values: dict[str, object], *hidden_text: str
) -> None:
    with pytest.raises(ValidationError) as exc_info:
        GenerationParameters.model_validate({"values": values})

    rendered = (
        str(exc_info.value),
        "".join(traceback.format_exception(exc_info.value)),
    )
    assert all("input_value" not in surface for surface in rendered)
    assert all("canonical v1 contract" in surface for surface in rendered)
    for text in hidden_text:
        assert all(text not in surface for surface in rendered)


def _assert_request_integrity_rejected_without_echoing(
    values: dict[str, object], *hidden_text: str
) -> None:
    with pytest.raises(ValidationError) as exc_info:
        GenerationRequestRecord.model_validate(values)

    rendered = (
        str(exc_info.value),
        "".join(traceback.format_exception(exc_info.value)),
    )
    assert all("input_value" not in surface for surface in rendered)
    assert all("generation request integrity validation failed" in surface for surface in rendered)
    for text in hidden_text:
        assert all(text not in surface for surface in rendered)


def test_generation_request_record_requires_explicit_supported_version() -> None:
    missing_version = _record_values()
    missing_version.pop("schema_version")

    with pytest.raises(ValidationError):
        GenerationRequestRecord.model_validate(missing_version)
    with pytest.raises(ValidationError):
        GenerationRequestRecord.model_validate(_record_values(schema_version="2.0"))

    record = GenerationRequestRecord.model_validate(_record_values())
    assert record.schema_version == "1.0"


@pytest.mark.parametrize("field", ["hypothesis_id", "intervention_id"])
def test_observed_request_rejects_counterfactual_identifiers(field: str) -> None:
    with pytest.raises(ValidationError):
        GenerationRequestRecord.model_validate(_record_values(**{field: "unexpected"}))


@pytest.mark.parametrize("missing_field", ["hypothesis_id", "intervention_id"])
def test_counterfactual_request_requires_both_identifiers(missing_field: str) -> None:
    identifiers = {"hypothesis_id": "hyp-1", "intervention_id": "int-1"}
    identifiers[missing_field] = None

    with pytest.raises(ValidationError):
        GenerationRequestRecord.model_validate(
            _record_values(condition="counterfactual", **identifiers)
        )


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("prompt", ""),
        ("request_id", f"request_{'a' * 64}"),
        ("request_id", f"req_{'A' * 64}"),
        ("prompt_sha256", "a" * 63),
        ("prompt_sha256", "A" * 64),
        ("system_template_sha256", "not-a-hash"),
        ("endpoint_type", "responses"),
    ],
)
def test_generation_request_record_rejects_invalid_contract_fields(
    field: str, invalid_value: str
) -> None:
    with pytest.raises(ValidationError):
        GenerationRequestRecord.model_validate(_record_values(**{field: invalid_value}))


@pytest.mark.parametrize("forged_field", ["prompt_sha256", "request_id"])
def test_generation_request_record_rejects_forged_integrity_fields_without_echoing(
    forged_field: str,
) -> None:
    secret_prompt = "sensitive prompt body for integrity validation"
    values = _record_values(prompt=secret_prompt)
    values[forged_field] = "0" * 64
    if forged_field == "request_id":
        values[forged_field] = f"req_{values[forged_field]}"

    _assert_request_integrity_rejected_without_echoing(
        values,
        secret_prompt,
        str(values[forged_field]),
    )


def test_generation_request_record_rejects_conflicting_parameter_seed() -> None:
    values = _record_values(
        seed_id=17,
        parameters=GenerationParameters(values={"seed": 23}),
    )

    _assert_request_integrity_rejected_without_echoing(values, "17", "23")


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("prompt_id", ""),
        ("prompt_id", "   "),
        ("language", ""),
        ("language", "   "),
        ("model_id", ""),
        ("model_id", "   "),
        ("system_template_version", ""),
        ("system_template_version", "   "),
    ],
)
def test_generation_request_record_rejects_blank_required_text_fields(
    field: str,
    invalid_value: str,
) -> None:
    with pytest.raises(ValidationError):
        GenerationRequestRecord.model_validate(_record_values(**{field: invalid_value}))


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [("hypothesis_id", ""), ("intervention_id", "   ")],
)
def test_counterfactual_request_rejects_blank_optional_identifiers(
    field: str,
    invalid_value: str,
) -> None:
    identifiers = {"hypothesis_id": "hyp-1", "intervention_id": "int-1"}
    identifiers[field] = invalid_value

    with pytest.raises(ValidationError):
        GenerationRequestRecord.model_validate(
            _record_values(condition="counterfactual", **identifiers)
        )


@pytest.mark.parametrize("invalid_seed", [True, "1", 1.0])
def test_generation_request_record_requires_strict_integer_seed(
    invalid_seed: object,
) -> None:
    with pytest.raises(ValidationError):
        GenerationRequestRecord.model_validate(_record_values(seed_id=invalid_seed))


@pytest.mark.parametrize("unknown_key", ["auth", "unknownProviderOption"])
def test_generation_request_record_hides_invalid_nested_parameter_input(
    unknown_key: str,
) -> None:
    secret = "nested-record-provider-secret"
    payload = _record_values(parameters={"values": {unknown_key: secret}})

    with pytest.raises(ValidationError) as exc_info:
        GenerationRequestRecord.model_validate(payload)

    rendered = (
        str(exc_info.value),
        "".join(traceback.format_exception(exc_info.value)),
    )
    for hidden_text in (unknown_key, secret, "input_value"):
        assert all(hidden_text not in surface for surface in rendered)


def test_generation_parameters_default_empty() -> None:
    assert GenerationParameters().values == {}


@pytest.mark.parametrize(
    ("parameter_name", "parameter_value"),
    [
        ("temperature", 0.2),
        ("top_p", 0.95),
        ("max_tokens", 128),
        ("max_completion_tokens", 128),
        ("max_output_tokens", 128),
        ("seed", 7),
        ("stop", ["END", "DONE"]),
        ("frequency_penalty", 0.0),
        ("presence_penalty", 0.0),
        ("n", 1),
        ("logprobs", True),
        ("top_logprobs", 5),
        ("reasoning_effort", "medium"),
        ("verbosity", "low"),
    ],
)
def test_generation_parameters_allow_every_v1_parameter(
    parameter_name: str, parameter_value: object
) -> None:
    parameters = GenerationParameters(values={parameter_name: parameter_value})

    assert parameters.values == {parameter_name: parameter_value}


@pytest.mark.parametrize(
    "unknown_key",
    [
        "tokenValue",
        "apiTokenValue",
        "accessTokenValue",
        "auth",
        "bearer",
        "arbitrary_unknown",
    ],
)
def test_generation_parameters_reject_unknown_keys_without_echoing_input(
    unknown_key: str,
) -> None:
    secret = "unknown-parameter-sensitive-value"

    _assert_parameters_rejected_without_echoing({unknown_key: secret}, unknown_key, secret)


@pytest.mark.parametrize(
    "values",
    [
        {"temperature": {"nestedSecretValue": "provider-secret-material"}},
        {"temperature": ["provider-secret-material"]},
        {"stop": [{"nestedSecretValue": "provider-secret-material"}]},
        {"stop": ["END", 7]},
    ],
)
def test_generation_parameters_reject_nested_or_non_string_list_values_without_leaking(
    values: dict[str, object],
) -> None:
    _assert_parameters_rejected_without_echoing(
        values,
        "nestedSecretValue",
        "provider-secret-material",
    )


@pytest.mark.parametrize(
    "numeric_key",
    [
        "temperature",
        "top_p",
        "max_tokens",
        "max_completion_tokens",
        "max_output_tokens",
        "seed",
        "frequency_penalty",
        "presence_penalty",
        "n",
        "top_logprobs",
    ],
)
def test_generation_parameters_reject_boolean_numeric_values(numeric_key: str) -> None:
    _assert_parameters_rejected_without_echoing({numeric_key: True}, "True")


@pytest.mark.parametrize(
    ("parameter_name", "invalid_value", "hidden_text"),
    [
        ("temperature", "wrong-temperature-value", "wrong-temperature-value"),
        ("top_p", None, "None"),
        ("frequency_penalty", "wrong-frequency-value", "wrong-frequency-value"),
        ("presence_penalty", None, "None"),
        ("max_tokens", None, "None"),
        ("max_tokens", 0, None),
        ("max_completion_tokens", -1, None),
        ("max_output_tokens", 1.5, None),
        ("n", 0, None),
        ("seed", 1.25, None),
        ("top_logprobs", -1, None),
        ("logprobs", "wrong-logprobs-value", "wrong-logprobs-value"),
        ("logprobs", 7, None),
        ("stop", 42, None),
        ("reasoning_effort", "", None),
        ("reasoning_effort", "   ", None),
        ("reasoning_effort", 7, None),
        ("verbosity", "", None),
        ("verbosity", None, "None"),
    ],
)
def test_generation_parameters_enforce_key_specific_types_without_leaking(
    parameter_name: str,
    invalid_value: object,
    hidden_text: str | None,
) -> None:
    hidden = () if hidden_text is None else (hidden_text,)
    _assert_parameters_rejected_without_echoing(
        {parameter_name: invalid_value},
        *hidden,
    )


@pytest.mark.parametrize(
    ("parameter_name", "valid_value"),
    [
        ("temperature", 1),
        ("seed", -1),
        ("top_logprobs", 0),
        ("stop", "END"),
    ],
)
def test_generation_parameters_accept_type_boundaries(
    parameter_name: str,
    valid_value: object,
) -> None:
    parameters = GenerationParameters(values={parameter_name: valid_value})

    assert parameters.values == {parameter_name: valid_value}


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_generation_parameters_reject_non_finite_numbers(value: float) -> None:
    with pytest.raises(ValidationError):
        GenerationParameters(values={"temperature": value})


def test_sha256_text_hashes_utf8_bytes() -> None:
    text = "路径 café"
    assert sha256_text(text) == hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_observed_grid_has_explicit_version_and_stable_coordinate_order() -> None:
    prompts = [_prompt("prompt-b"), _prompt("prompt-a")]

    records = plan_observed_requests(
        prompts,
        ["model-z", "model-a"],
        [9, 1],
        endpoint_type="offline",
    )

    assert len(records) == 8
    assert all(record.schema_version == "1.0" for record in records)
    assert [
        (record.prompt_id, record.model_id, record.seed_id) for record in records
    ] == [
        (prompt_id, model_id, seed_id)
        for prompt_id in ("prompt-a", "prompt-b")
        for model_id in ("model-a", "model-z")
        for seed_id in (1, 9)
    ]


def test_observed_planning_rejects_empty_materialized_prompts() -> None:
    with pytest.raises(SecAwareError) as exc_info:
        plan_observed_requests(
            (prompt for prompt in []),
            ["model-a"],
            [1],
            endpoint_type="mock",
        )

    assert exc_info.value.code is ErrorCode.CONTRACT


def test_observed_planning_rejects_duplicate_prompt_ids_without_echoing_prompts() -> None:
    prompt_id = "sensitive-duplicate-prompt-id"
    first_text = "first sensitive prompt text"
    second_text = "second sensitive prompt text"
    prompts = [_prompt(prompt_id, first_text), _prompt(prompt_id, second_text)]

    with pytest.raises(SecAwareError) as exc_info:
        plan_observed_requests(
            (prompt for prompt in prompts),
            ["model-a"],
            [1],
            endpoint_type="mock",
        )

    error = exc_info.value
    assert error.code is ErrorCode.CONTRACT
    for hidden_text in (prompt_id, first_text, second_text):
        assert hidden_text not in str(error)
        assert hidden_text not in str(error.to_dict())


def test_observed_planning_is_independent_of_input_order() -> None:
    prompts = [_prompt("prompt-a"), _prompt("prompt-b")]

    forward = plan_observed_requests(
        prompts,
        ["model-a", "model-b"],
        [1, 2],
        endpoint_type="mock",
    )
    reversed_inputs = plan_observed_requests(
        reversed(prompts),
        ["model-b", "model-a"],
        [2, 1],
        endpoint_type="mock",
    )

    assert reversed_inputs == forward


def test_request_identity_includes_schema_version_and_language() -> None:
    python_prompt = _prompt("prompt-language", "Generate the same implementation.")
    javascript_prompt = python_prompt.model_copy(update={"language": "javascript"})

    python_record = plan_observed_requests(
        [python_prompt], ["model-a"], [1], endpoint_type="mock"
    )[0]
    javascript_record = plan_observed_requests(
        [javascript_prompt], ["model-a"], [1], endpoint_type="mock"
    )[0]

    assert python_record.request_id == _expected_request_id(
        python_record.model_dump(mode="python")
    )
    assert python_record.request_id != javascript_record.request_id


def test_parameter_mapping_order_does_not_change_request_id() -> None:
    prompt = _prompt("prompt-a")
    first = GenerationParameters(values={"temperature": 0, "top_p": 1})
    reordered = GenerationParameters(values={"top_p": 1, "temperature": 0})

    first_record = plan_observed_requests(
        [prompt], ["model-a"], [1], endpoint_type="chat_completions", parameters=first
    )[0]
    reordered_record = plan_observed_requests(
        [prompt], ["model-a"], [1], endpoint_type="chat_completions", parameters=reordered
    )[0]

    assert first_record.request_id == reordered_record.request_id


def test_system_template_is_hashed_and_bound_to_request_identity() -> None:
    prompt = _prompt("prompt-a")

    first = plan_observed_requests(
        [prompt],
        ["model-a"],
        [1],
        endpoint_type="mock",
        system_template="system alpha",
        system_template_version="v1",
    )[0]
    second = plan_observed_requests(
        [prompt],
        ["model-a"],
        [1],
        endpoint_type="mock",
        system_template="system beta",
        system_template_version="v1",
    )[0]

    assert first.system_template_sha256 == sha256_text("system alpha")
    assert first.request_id != second.request_id
    assert "system alpha" not in first.model_dump_json()


def test_counterfactual_uses_patched_text_hash_and_identifiers() -> None:
    prompt = _prompt("prompt-a")
    intervention = _intervention(
        prompt,
        hypothesis_id="hyp-a",
        intervention_id="int-a",
        counterfactual_prompt="Validate and normalize the supplied path.",
    )

    record = plan_counterfactual_requests(
        {prompt.prompt_id: prompt},
        [intervention],
        ["model-a"],
        [1],
        endpoint_type="mock",
    )[0]

    assert record.condition == "counterfactual"
    assert record.prompt == intervention.counterfactual_prompt
    assert record.prompt_sha256 == sha256_text(intervention.counterfactual_prompt)
    assert record.hypothesis_id == intervention.hypothesis_id
    assert record.intervention_id == intervention.intervention_id


def test_observed_and_counterfactual_request_ids_do_not_collide() -> None:
    prompt = _prompt("prompt-a")
    intervention = _intervention(prompt, counterfactual_prompt=prompt.prompt)

    observed = plan_observed_requests(
        [prompt], ["model-a"], [1], endpoint_type="mock"
    )[0]
    counterfactual = plan_counterfactual_requests(
        {prompt.prompt_id: prompt},
        [intervention],
        ["model-a"],
        [1],
        endpoint_type="mock",
    )[0]

    assert observed.request_id != counterfactual.request_id


def test_counterfactual_planning_is_independent_of_all_input_order() -> None:
    prompt_a = _prompt("prompt-a")
    prompt_b = _prompt("prompt-b")
    interventions = [
        _intervention(prompt_b, hypothesis_id="hyp-b", intervention_id="int-b"),
        _intervention(prompt_a, hypothesis_id="hyp-a", intervention_id="int-a"),
    ]

    forward = plan_counterfactual_requests(
        {"prompt-a": prompt_a, "prompt-b": prompt_b},
        interventions,
        ["model-a", "model-b"],
        [1, 2],
        endpoint_type="offline",
    )
    reversed_inputs = plan_counterfactual_requests(
        {"prompt-b": prompt_b, "prompt-a": prompt_a},
        reversed(interventions),
        ["model-b", "model-a"],
        [2, 1],
        endpoint_type="offline",
    )

    assert reversed_inputs == forward


def test_counterfactual_planning_rejects_empty_materialized_interventions() -> None:
    prompt = _prompt("prompt-a")

    with pytest.raises(SecAwareError) as exc_info:
        plan_counterfactual_requests(
            {prompt.prompt_id: prompt},
            (intervention for intervention in []),
            ["model-a"],
            [1],
            endpoint_type="mock",
        )

    assert exc_info.value.code is ErrorCode.CONTRACT


def test_counterfactual_planning_rejects_duplicate_intervention_ids_safely() -> None:
    prompt_a = _prompt("sensitive-prompt-a", "first original sensitive prompt")
    prompt_b = _prompt("sensitive-prompt-b", "second original sensitive prompt")
    intervention_id = "sensitive-duplicate-intervention-id"
    interventions = [
        _intervention(
            prompt_a,
            hypothesis_id="hyp-a",
            intervention_id=intervention_id,
            counterfactual_prompt="first sensitive counterfactual",
        ),
        _intervention(
            prompt_b,
            hypothesis_id="hyp-b",
            intervention_id=intervention_id,
            counterfactual_prompt="second sensitive counterfactual",
        ),
    ]

    with pytest.raises(SecAwareError) as exc_info:
        plan_counterfactual_requests(
            {prompt_a.prompt_id: prompt_a, prompt_b.prompt_id: prompt_b},
            (intervention for intervention in interventions),
            ["model-a"],
            [1],
            endpoint_type="mock",
        )

    error = exc_info.value
    assert error.code is ErrorCode.CONTRACT
    for hidden_text in (
        prompt_a.prompt,
        prompt_b.prompt,
        interventions[0].counterfactual_prompt,
        interventions[1].counterfactual_prompt,
        intervention_id,
    ):
        assert hidden_text not in str(error)
        assert hidden_text not in str(error.to_dict())


def test_counterfactual_planning_rejects_duplicate_generation_coordinates() -> None:
    prompt = _prompt("prompt-coordinate")
    interventions = [
        _intervention(prompt, counterfactual_prompt="first coordinate text"),
        _intervention(prompt, counterfactual_prompt="second coordinate text"),
    ]

    with pytest.raises(SecAwareError) as exc_info:
        plan_counterfactual_requests(
            {prompt.prompt_id: prompt},
            interventions,
            ["model-a"],
            [1],
            endpoint_type="mock",
        )

    assert exc_info.value.code is ErrorCode.CONTRACT


def test_counterfactual_missing_prompt_raises_safe_contract_error() -> None:
    prompt = _prompt("prompt-missing-sensitive-id")
    intervention = _intervention(prompt)

    with pytest.raises(SecAwareError) as exc_info:
        plan_counterfactual_requests(
            {}, [intervention], ["model-a"], [1], endpoint_type="mock"
        )

    error = exc_info.value
    assert error.code is ErrorCode.CONTRACT
    assert prompt.prompt_id not in str(error)
    assert prompt.prompt_id not in str(error.to_dict())


@pytest.mark.parametrize(
    ("models", "seeds"),
    [
        ([], [1]),
        (["model-a", "model-a"], [1]),
        (["model-a"], []),
        (["model-a"], [1, 1]),
    ],
)
def test_empty_or_duplicate_grid_axes_raise_config(
    models: list[str], seeds: list[int]
) -> None:
    with pytest.raises(SecAwareError) as exc_info:
        plan_observed_requests([_prompt("prompt-a")], models, seeds, endpoint_type="mock")

    assert exc_info.value.code is ErrorCode.CONFIG


def test_duplicate_request_id_raises_contract() -> None:
    prompt = _prompt("prompt-a")

    with pytest.raises(SecAwareError) as exc_info:
        plan_observed_requests(
            [prompt, prompt], ["model-a"], [1], endpoint_type="mock"
        )

    assert exc_info.value.code is ErrorCode.CONTRACT

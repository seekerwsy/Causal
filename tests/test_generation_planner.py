from collections.abc import Callable, Iterator, Mapping
import hashlib
import json
import traceback

import pytest
from pydantic import ValidationError, model_validator

from secaware.errors import ErrorCode, SecAwareError
from secaware.generation import request_planner
from secaware.generation.request_planner import (
    plan_counterfactual_requests,
    plan_observed_requests,
    sha256_text,
)
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema import generation as generation_schema
from secaware.schema.generation import (
    GENERATION_REQUEST_SCHEMA_VERSION,
    GenerationParameters,
    GenerationRequestRecord,
)
from secaware.schema.hypotheses import FactorType
from secaware.schema.interventions import InterventionRecord
from secaware.schema.records import PromptRecord


def _prompt(prompt_id: str, text: str | None = None) -> PromptRecord:
    return PromptRecord(
        prompt_id=prompt_id,
        task_id=f"task-{prompt_id}",
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


class GuardedInfiniteIterator:
    def __init__(
        self,
        factory: Callable[[int], object],
        *,
        maximum_reads: int,
    ) -> None:
        self.factory = factory
        self.maximum_reads = maximum_reads
        self.reads = 0

    def __iter__(self) -> "GuardedInfiniteIterator":
        return self

    def __next__(self) -> object:
        self.reads += 1
        if self.reads > self.maximum_reads:
            raise RuntimeError("unbounded-materialization-overread-secret")
        return self.factory(self.reads)


def _valid_parameter_value(key: str) -> object:
    if key in {"temperature", "top_p", "frequency_penalty", "presence_penalty"}:
        return 0.0
    if key in {"max_tokens", "max_completion_tokens", "max_output_tokens", "n"}:
        return 1
    if key in {"seed", "top_logprobs"}:
        return 0
    if key == "logprobs":
        return False
    if key == "stop":
        return "END"
    return "low"


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
        "endpoint_sha256": values["endpoint_sha256"],
        "system_template_version": values["system_template_version"],
        "system_template_sha256": values["system_template_sha256"],
        "parameters": parameters,
    }
    return f"req_{canonical_sha256(identity)}"


def _record_values(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "schema_version": GENERATION_REQUEST_SCHEMA_VERSION,
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
        "endpoint_sha256": sha256_text("mock"),
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


def _assert_sanitized_validation_error(
    error: ValidationError,
    *,
    expected_message: str,
    hidden_text: tuple[str, ...],
) -> None:
    assert error.__cause__ is None
    assert error.__context__ is None
    structured = error.errors()
    assert len(structured) == 1
    assert structured[0]["loc"] == ()
    assert structured[0].get("input") is None
    assert "ctx" not in structured[0]
    assert expected_message in structured[0]["msg"]

    surfaces = (
        str(error),
        "".join(traceback.format_exception(error)),
        json.dumps(structured, default=str),
        error.json(),
    )
    for text in hidden_text:
        assert all(text not in surface for surface in surfaces)


@pytest.mark.parametrize(
    "entrypoint",
    ["constructor", "model_validate", "model_validate_json", "model_validate_strings"],
)
def test_generation_parameters_public_validation_errors_are_fully_sanitized(
    entrypoint: str,
) -> None:
    sensitive_key = "api_key"
    secret = "parameter-validation-surface-secret"
    payload = {"values": {sensitive_key: secret}}

    with pytest.raises(ValidationError) as exc_info:
        if entrypoint == "constructor":
            GenerationParameters(**payload)
        elif entrypoint == "model_validate":
            GenerationParameters.model_validate(payload)
        elif entrypoint == "model_validate_json":
            GenerationParameters.model_validate_json(json.dumps(payload))
        else:
            GenerationParameters.model_validate_strings(payload)

    _assert_sanitized_validation_error(
        exc_info.value,
        expected_message="generation parameters do not match the canonical v1 contract",
        hidden_text=(sensitive_key, secret),
    )


@pytest.mark.parametrize(
    "entrypoint",
    ["constructor", "model_validate", "model_validate_json", "model_validate_strings"],
)
def test_generation_request_public_validation_errors_are_fully_sanitized(
    entrypoint: str,
) -> None:
    sensitive_key = "api_key"
    secret = "request-validation-surface-secret"
    payload = _record_values(parameters={"values": {sensitive_key: secret}})

    with pytest.raises(ValidationError) as exc_info:
        if entrypoint == "constructor":
            GenerationRequestRecord(**payload)
        elif entrypoint == "model_validate":
            GenerationRequestRecord.model_validate(payload)
        elif entrypoint == "model_validate_json":
            GenerationRequestRecord.model_validate_json(json.dumps(payload))
        else:
            GenerationRequestRecord.model_validate_strings({"prompt": secret})

    _assert_sanitized_validation_error(
        exc_info.value,
        expected_message="generation request integrity validation failed",
        hidden_text=(sensitive_key, secret),
    )


@pytest.mark.parametrize(
    "entrypoint",
    ["constructor", "model_validate", "model_validate_json", "model_validate_strings"],
)
def test_generation_validation_mixin_sanitizes_runtime_errors(
    entrypoint: str,
) -> None:
    secret = "validation-runtime-encode-secret"

    class ExplodingText(str):
        def encode(self, *args: object, **kwargs: object) -> bytes:
            raise RuntimeError(secret)

    class ExplodingParameters(GenerationParameters):
        @model_validator(mode="before")
        @classmethod
        def raise_runtime_error(cls, value: object) -> object:
            ExplodingText("value").encode()
            return value

    with pytest.raises(ValidationError) as exc_info:
        if entrypoint == "constructor":
            ExplodingParameters(values={})
        elif entrypoint == "model_validate":
            ExplodingParameters.model_validate({"values": {}})
        elif entrypoint == "model_validate_json":
            ExplodingParameters.model_validate_json('{"values": {}}')
        else:
            ExplodingParameters.model_validate_strings({"values": {}})

    _assert_sanitized_validation_error(
        exc_info.value,
        expected_message="generation parameters do not match the canonical v1 contract",
        hidden_text=(secret, "RuntimeError"),
    )


@pytest.mark.parametrize(
    "entrypoint",
    ["constructor", "model_validate", "model_validate_strings"],
)
def test_generation_parameters_reject_hostile_string_subclasses_safely(
    entrypoint: str,
) -> None:
    secret = "validation-runtime-strip-secret"

    class ExplodingText(str):
        def strip(self, *args: object, **kwargs: object) -> str:
            raise RuntimeError(secret)

    payload = {"values": {"reasoning_effort": ExplodingText("medium")}}
    with pytest.raises(ValidationError) as exc_info:
        if entrypoint == "constructor":
            GenerationParameters(**payload)
        elif entrypoint == "model_validate":
            GenerationParameters.model_validate(payload)
        else:
            GenerationParameters.model_validate_strings(payload)

    _assert_sanitized_validation_error(
        exc_info.value,
        expected_message="generation parameters do not match the canonical v1 contract",
        hidden_text=(secret, "RuntimeError"),
    )


@pytest.mark.parametrize("signal", [KeyboardInterrupt, SystemExit])
def test_generation_validation_mixin_does_not_swallow_base_exceptions(
    signal: type[BaseException],
) -> None:
    class InterruptingParameters(GenerationParameters):
        @model_validator(mode="before")
        @classmethod
        def interrupt(cls, value: object) -> object:
            raise signal()

    with pytest.raises(signal):
        InterruptingParameters.model_validate({"values": {}})


def test_generation_request_record_requires_explicit_supported_version() -> None:
    missing_version = _record_values()
    missing_version.pop("schema_version")

    with pytest.raises(ValidationError):
        GenerationRequestRecord.model_validate(missing_version)
    with pytest.raises(ValidationError):
        GenerationRequestRecord.model_validate(_record_values(schema_version="2.0"))

    record = GenerationRequestRecord.model_validate(_record_values())
    assert record.schema_version == GENERATION_REQUEST_SCHEMA_VERSION


def test_generation_request_record_requires_endpoint_hash_and_binds_it_to_identity() -> None:
    missing = _record_values()
    missing.pop("endpoint_sha256")
    with pytest.raises(ValidationError):
        GenerationRequestRecord.model_validate(missing)

    original = GenerationRequestRecord.model_validate(_record_values())
    changed_values = _record_values(endpoint_sha256=sha256_text("https://other.invalid/v1"))
    changed = GenerationRequestRecord.model_validate(changed_values)

    assert original.endpoint_sha256 == sha256_text("mock")
    assert changed.request_id != original.request_id


def test_planner_hashes_explicit_endpoint_identity_without_serializing_it() -> None:
    endpoint = "https://provider-secret.invalid/v1"
    record = plan_observed_requests(
        [_prompt("prompt-endpoint")],
        ["model-a"],
        [1],
        endpoint_type="chat_completions",
        endpoint_identity=endpoint,
    )[0]

    assert record.endpoint_sha256 == sha256_text(endpoint)
    assert endpoint not in record.model_dump_json()


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
        seed_id=903_417,
        parameters=GenerationParameters(values={"seed": 903_418}),
    )

    _assert_request_integrity_rejected_without_echoing(values, "903417", "903418")


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


def test_generation_parameter_mapping_is_read_only() -> None:
    secret = "mutation-injected-provider-secret"
    parameters = GenerationParameters(values={"temperature": 0.2})

    with pytest.raises(TypeError):
        parameters.values["api_key"] = secret

    assert parameters.values == {"temperature": 0.2}
    assert secret not in parameters.model_dump_json()


def test_generation_parameter_nested_values_are_read_only_and_dump_as_json() -> None:
    parameters = GenerationParameters(values={"stop": ["END", "DONE"]})
    original_dump = parameters.model_dump(mode="json")
    original_hash = canonical_sha256(original_dump)
    stop = parameters.values["stop"]

    with pytest.raises((AttributeError, TypeError)):
        stop.append("mutation-injected-provider-secret")

    assert stop == ["END", "DONE"]
    assert parameters.values == {"stop": ["END", "DONE"]}
    assert parameters.model_dump(mode="json") == {"values": {"stop": ["END", "DONE"]}}
    assert isinstance(parameters.model_dump(mode="json")["values"], dict)
    assert isinstance(parameters.model_dump(mode="json")["values"]["stop"], list)
    assert canonical_sha256(parameters.model_dump(mode="json")) == original_hash


def test_generation_parameters_snapshot_nested_containers_before_validation() -> None:
    secret = "snapshot-race-injected-provider-secret"

    class MutatingStopList(list[object]):
        def __iter__(self):  # type: ignore[no-untyped-def]
            stale_values = list.copy(self)
            list.__setitem__(self, 0, {"api_key": secret})
            return iter(stale_values)

    parameters = GenerationParameters(values={"stop": MutatingStopList(["END"])})

    assert parameters.values == {"stop": ["END"]}
    assert parameters.model_dump(mode="json") == {"values": {"stop": ["END"]}}
    assert secret not in parameters.model_dump_json()


def test_generation_parameters_bound_top_level_mapping_consumption() -> None:
    known_keys = sorted(generation_schema._V1_PARAMETER_KEYS)
    limit = len(known_keys)

    class GuardedParameterMapping(Mapping[str, object]):
        def __init__(self) -> None:
            self.key_reads = 0
            self.value_reads = 0

        def __iter__(self) -> Iterator[str]:
            for key in known_keys:
                self.key_reads += 1
                yield key
            self.key_reads += 1
            yield "overflow-unknown-key"
            raise RuntimeError("parameter-mapping-overread-secret")

        def __getitem__(self, key: str) -> object:
            self.value_reads += 1
            return _valid_parameter_value(key)

        def __len__(self) -> int:
            return 10_000

    source = GuardedParameterMapping()
    with pytest.raises(ValidationError) as exc_info:
        GenerationParameters(values=source)

    _assert_sanitized_validation_error(
        exc_info.value,
        expected_message="generation parameters do not match the canonical v1 contract",
        hidden_text=("parameter-mapping-overread-secret",),
    )
    assert source.key_reads == limit + 1
    assert source.value_reads == limit


def test_generation_parameters_reject_unknown_key_without_reading_its_value() -> None:
    secret = "unknown-parameter-value-read-secret"

    class UnknownKeyMapping(Mapping[str, object]):
        def __init__(self) -> None:
            self.value_reads = 0

        def __iter__(self) -> Iterator[str]:
            yield "api_key"

        def __getitem__(self, key: str) -> object:
            self.value_reads += 1
            raise RuntimeError(secret)

        def __len__(self) -> int:
            return 1

    source = UnknownKeyMapping()
    with pytest.raises(ValidationError) as exc_info:
        GenerationParameters(values=source)

    _assert_sanitized_validation_error(
        exc_info.value,
        expected_message="generation parameters do not match the canonical v1 contract",
        hidden_text=("api_key", secret),
    )
    assert source.value_reads == 0


def test_generation_parameters_bound_stop_list_consumption() -> None:
    limit = getattr(generation_schema, "MAX_STOP_PARAMETER_ITEMS", 64)

    class GuardedStopList(list[str]):
        def __init__(self) -> None:
            super().__init__()
            self.reads = 0

        def __iter__(self) -> Iterator[str]:
            while True:
                self.reads += 1
                if self.reads > limit + 1:
                    raise RuntimeError("stop-list-overread-secret")
                yield "END"

    stop = GuardedStopList()
    with pytest.raises(ValidationError) as exc_info:
        GenerationParameters(values={"stop": stop})

    _assert_sanitized_validation_error(
        exc_info.value,
        expected_message="generation parameters do not match the canonical v1 contract",
        hidden_text=("stop-list-overread-secret",),
    )
    assert stop.reads == limit + 1


@pytest.mark.parametrize("source_kind", ["mapping", "stop_list"])
def test_generation_parameters_sanitize_source_iteration_errors(
    source_kind: str,
) -> None:
    secret = "parameter-source-iteration-secret"

    class RaisingMapping(Mapping[str, object]):
        def __iter__(self) -> Iterator[str]:
            yield "temperature"

        def __getitem__(self, key: str) -> object:
            raise RuntimeError(secret)

        def __len__(self) -> int:
            return 1

    class RaisingStopList(list[str]):
        def __iter__(self) -> Iterator[str]:
            raise RuntimeError(secret)

    values: object = RaisingMapping()
    if source_kind == "stop_list":
        values = {"stop": RaisingStopList()}

    with pytest.raises(ValidationError) as exc_info:
        GenerationParameters.model_validate({"values": values})

    _assert_sanitized_validation_error(
        exc_info.value,
        expected_message="generation parameters do not match the canonical v1 contract",
        hidden_text=(secret, "RuntimeError"),
    )


def test_generation_parameters_do_not_retain_source_container_aliases() -> None:
    source_stop = ["END"]
    source = {"stop": source_stop}
    parameters = GenerationParameters(values=source)

    source_stop.append("source-mutation")
    source["temperature"] = 0.9

    assert parameters.values == {"stop": ["END"]}
    assert parameters.model_dump(mode="json") == {"values": {"stop": ["END"]}}


def test_valid_nested_parameter_instances_survive_revalidation_as_json_lists() -> None:
    parameters = GenerationParameters(values={"stop": ["END", "DONE"]})

    planned = plan_observed_requests(
        [_prompt("prompt-a")],
        ["model-a"],
        [1],
        endpoint_type="mock",
        parameters=parameters,
    )[0]
    direct = GenerationRequestRecord.model_validate(_record_values(parameters=parameters))

    for record in (planned, direct):
        assert record.parameters.values == {"stop": ["END", "DONE"]}
        assert record.model_dump(mode="json")["parameters"] == {"values": {"stop": ["END", "DONE"]}}


def test_generation_parameters_model_is_frozen() -> None:
    parameters = GenerationParameters(values={"temperature": 0.2})

    with pytest.raises(ValidationError):
        parameters.values = {"temperature": 0.9}

    assert parameters.values == {"temperature": 0.2}


def test_planner_revalidates_untrusted_generation_parameter_instances() -> None:
    unknown_key = "untrustedPlannerOption"
    secret = "planner-model-construct-provider-secret"
    untrusted = GenerationParameters.model_construct(values={unknown_key: secret})

    with pytest.raises(SecAwareError) as exc_info:
        plan_observed_requests(
            [_prompt("prompt-a")],
            ["model-a"],
            [1],
            endpoint_type="mock",
            parameters=untrusted,
        )

    rendered = (
        str(exc_info.value),
        "".join(traceback.format_exception(exc_info.value)),
        json.dumps(exc_info.value.to_dict(), sort_keys=True),
    )
    assert exc_info.value.code is ErrorCode.CONTRACT
    for hidden_text in (unknown_key, secret, "input_value"):
        assert all(hidden_text not in surface for surface in rendered)


def test_planner_safely_wraps_parameter_mapping_snapshot_failures() -> None:
    secret = "parameter-mapping-iteration-secret"

    class RaisingMapping(Mapping[str, object]):
        def __getitem__(self, key: str) -> object:
            raise RuntimeError(secret)

        def __iter__(self) -> Iterator[str]:
            return iter(("temperature",))

        def __len__(self) -> int:
            return 1

    with pytest.raises(SecAwareError) as exc_info:
        plan_observed_requests(
            [_prompt("prompt-a")],
            ["model-a"],
            [1],
            endpoint_type="mock",
            parameters=RaisingMapping(),
        )

    error = exc_info.value
    assert error.code is ErrorCode.CONTRACT
    rendered = (
        str(error),
        "".join(traceback.format_exception(error)),
        json.dumps(error.to_dict(), sort_keys=True),
    )
    for hidden_text in (secret, "RuntimeError"):
        assert all(hidden_text not in surface for surface in rendered)


def test_planner_safely_wraps_hostile_parameter_scalar() -> None:
    secret = "planner-parameter-strip-secret"

    class ExplodingText(str):
        def strip(self, *args: object, **kwargs: object) -> str:
            raise RuntimeError(secret)

    with pytest.raises(SecAwareError) as exc_info:
        plan_observed_requests(
            [_prompt("prompt-a")],
            ["model-a"],
            [1],
            endpoint_type="mock",
            parameters={"reasoning_effort": ExplodingText("medium")},
        )

    assert exc_info.value.code is ErrorCode.CONTRACT
    rendered = (
        str(exc_info.value),
        "".join(traceback.format_exception(exc_info.value)),
        json.dumps(exc_info.value.to_dict(), sort_keys=True),
    )
    for hidden_text in (secret, "RuntimeError"):
        assert all(hidden_text not in surface for surface in rendered)


def test_generation_request_revalidates_untrusted_nested_parameter_instances() -> None:
    unknown_key = "untrustedRecordOption"
    secret = "record-model-construct-provider-secret"
    untrusted = GenerationParameters.model_construct(values={unknown_key: secret})
    payload = _record_values(parameters=untrusted)

    with pytest.raises(ValidationError) as exc_info:
        GenerationRequestRecord.model_validate(payload)

    rendered = (
        str(exc_info.value),
        "".join(traceback.format_exception(exc_info.value)),
    )
    for hidden_text in (unknown_key, secret, "input_value"):
        assert all(hidden_text not in surface for surface in rendered)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("prompt", "changed prompt"),
        ("model_id", "changed-model"),
        ("parameters", GenerationParameters(values={"temperature": 0.9})),
    ],
)
def test_generation_request_identity_fields_are_frozen(
    field: str,
    replacement: object,
) -> None:
    record = plan_observed_requests(
        [_prompt("prompt-a")],
        ["model-a"],
        [1],
        endpoint_type="mock",
        parameters={"temperature": 0.2},
    )[0]
    original = record.model_dump(mode="json")

    with pytest.raises(ValidationError):
        setattr(record, field, replacement)

    assert record.model_dump(mode="json") == original


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
    ("parameter_name", "parameter_value"),
    [
        ("max_tokens", type("IntegerSubclass", (int,), {})(1)),
        ("temperature", type("FloatSubclass", (float,), {})(0.2)),
    ],
)
def test_generation_parameters_require_exact_builtin_scalars(
    parameter_name: str,
    parameter_value: object,
) -> None:
    with pytest.raises(ValidationError):
        GenerationParameters(values={parameter_name: parameter_value})


@pytest.mark.parametrize(
    ("parameter_name", "invalid_value", "hidden_text"),
    [
        ("temperature", "wrong-temperature-value", "wrong-temperature-value"),
        ("top_p", None, None),
        ("frequency_penalty", "wrong-frequency-value", "wrong-frequency-value"),
        ("presence_penalty", None, None),
        ("max_tokens", None, None),
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
        ("verbosity", None, None),
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
    assert all(record.schema_version == GENERATION_REQUEST_SCHEMA_VERSION for record in records)
    assert [(record.prompt_id, record.model_id, record.seed_id) for record in records] == [
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

    python_record = plan_observed_requests([python_prompt], ["model-a"], [1], endpoint_type="mock")[
        0
    ]
    javascript_record = plan_observed_requests(
        [javascript_prompt], ["model-a"], [1], endpoint_type="mock"
    )[0]

    assert python_record.request_id == _expected_request_id(python_record.model_dump(mode="python"))
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

    observed = plan_observed_requests([prompt], ["model-a"], [1], endpoint_type="mock")[0]
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
        plan_counterfactual_requests({}, [intervention], ["model-a"], [1], endpoint_type="mock")

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
def test_empty_or_duplicate_grid_axes_raise_config(models: list[str], seeds: list[int]) -> None:
    with pytest.raises(SecAwareError) as exc_info:
        plan_observed_requests([_prompt("prompt-a")], models, seeds, endpoint_type="mock")

    assert exc_info.value.code is ErrorCode.CONFIG


def test_duplicate_request_id_raises_contract() -> None:
    prompt = _prompt("prompt-a")

    with pytest.raises(SecAwareError) as exc_info:
        plan_observed_requests([prompt, prompt], ["model-a"], [1], endpoint_type="mock")

    assert exc_info.value.code is ErrorCode.CONTRACT


@pytest.mark.parametrize(
    ("axis", "expected_code"),
    [
        ("prompts", ErrorCode.CONTRACT),
        ("models", ErrorCode.CONFIG),
        ("seeds", ErrorCode.CONFIG),
    ],
)
def test_observed_planner_materializes_each_iterable_with_a_bound(
    axis: str,
    expected_code: ErrorCode,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limit = 3
    monkeypatch.setattr(
        request_planner,
        "MAX_GENERATION_AXIS_ITEMS",
        limit,
        raising=False,
    )
    factories: dict[str, Callable[[int], object]] = {
        "prompts": lambda index: _prompt(f"prompt-{index}"),
        "models": lambda index: f"model-{index}",
        "seeds": lambda index: index,
    }
    guarded = GuardedInfiniteIterator(
        factories[axis],
        maximum_reads=limit + 1,
    )
    prompts: object = [_prompt("prompt-a")]
    models: object = ["model-a"]
    seeds: object = [1]
    if axis == "prompts":
        prompts = guarded
    elif axis == "models":
        models = guarded
    else:
        seeds = guarded

    with pytest.raises(SecAwareError) as exc_info:
        plan_observed_requests(
            prompts,  # type: ignore[arg-type]
            models,  # type: ignore[arg-type]
            seeds,  # type: ignore[arg-type]
            endpoint_type="mock",
        )

    assert exc_info.value.code is expected_code
    assert guarded.reads == limit + 1
    assert "overread-secret" not in "".join(traceback.format_exception(exc_info.value))


@pytest.mark.parametrize(
    ("axis", "expected_code"),
    [
        ("interventions", ErrorCode.CONTRACT),
        ("models", ErrorCode.CONFIG),
        ("seeds", ErrorCode.CONFIG),
    ],
)
def test_counterfactual_planner_materializes_each_iterable_with_a_bound(
    axis: str,
    expected_code: ErrorCode,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limit = 3
    monkeypatch.setattr(
        request_planner,
        "MAX_GENERATION_AXIS_ITEMS",
        limit,
        raising=False,
    )
    prompt = _prompt("prompt-a")
    factories: dict[str, Callable[[int], object]] = {
        "interventions": lambda index: _intervention(
            prompt,
            hypothesis_id=f"hyp-{index}",
            intervention_id=f"int-{index}",
        ),
        "models": lambda index: f"model-{index}",
        "seeds": lambda index: index,
    }
    guarded = GuardedInfiniteIterator(
        factories[axis],
        maximum_reads=limit + 1,
    )
    interventions: object = [_intervention(prompt)]
    models: object = ["model-a"]
    seeds: object = [1]
    if axis == "interventions":
        interventions = guarded
    elif axis == "models":
        models = guarded
    else:
        seeds = guarded

    with pytest.raises(SecAwareError) as exc_info:
        plan_counterfactual_requests(
            {prompt.prompt_id: prompt},
            interventions,  # type: ignore[arg-type]
            models,  # type: ignore[arg-type]
            seeds,  # type: ignore[arg-type]
            endpoint_type="mock",
        )

    assert exc_info.value.code is expected_code
    assert guarded.reads == limit + 1
    assert "overread-secret" not in "".join(traceback.format_exception(exc_info.value))


@pytest.mark.parametrize("condition", ["observed", "counterfactual"])
def test_planner_rejects_request_products_before_record_construction(
    condition: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        request_planner,
        "MAX_GENERATION_AXIS_ITEMS",
        10,
        raising=False,
    )
    monkeypatch.setattr(
        request_planner,
        "MAX_GENERATION_REQUESTS",
        3,
        raising=False,
    )

    def forbidden_record(**kwargs: object) -> None:
        raise AssertionError("request-product-was-built-secret")

    monkeypatch.setattr(request_planner, "_record", forbidden_record)

    with pytest.raises(SecAwareError) as exc_info:
        if condition == "observed":
            plan_observed_requests(
                [_prompt("prompt-a"), _prompt("prompt-b")],
                ["model-a", "model-b"],
                [1],
                endpoint_type="mock",
            )
        else:
            prompt = _prompt("prompt-a")
            plan_counterfactual_requests(
                {prompt.prompt_id: prompt},
                [
                    _intervention(prompt, intervention_id="int-a"),
                    _intervention(prompt, intervention_id="int-b"),
                ],
                ["model-a", "model-b"],
                [1],
                endpoint_type="mock",
            )

    assert exc_info.value.code is ErrorCode.CONFIG
    assert "request-product-was-built-secret" not in "".join(
        traceback.format_exception(exc_info.value)
    )


@pytest.mark.parametrize("condition", ["observed", "counterfactual"])
def test_planner_safely_wraps_input_iterator_failures(condition: str) -> None:
    secret = "generation-input-iterator-secret"

    def failing_values(first: object):
        yield first
        raise RuntimeError(secret)

    with pytest.raises(SecAwareError) as exc_info:
        if condition == "observed":
            plan_observed_requests(
                failing_values(_prompt("prompt-a")),
                ["model-a"],
                [1],
                endpoint_type="mock",
            )
        else:
            prompt = _prompt("prompt-a")
            plan_counterfactual_requests(
                {prompt.prompt_id: prompt},
                failing_values(_intervention(prompt)),
                ["model-a"],
                [1],
                endpoint_type="mock",
            )

    assert exc_info.value.code is ErrorCode.CONTRACT
    rendered = (
        str(exc_info.value),
        "".join(traceback.format_exception(exc_info.value)),
        json.dumps(exc_info.value.to_dict(), sort_keys=True),
    )
    for hidden_text in (secret, "RuntimeError"):
        assert all(hidden_text not in surface for surface in rendered)


def test_observed_planner_snapshots_each_prompt_as_it_is_consumed() -> None:
    first = _prompt("prompt-a", "original prompt text")
    second = _prompt("prompt-b", "second prompt text")
    mutation = "generator-mutated-prompt-secret"

    def prompt_stream():
        yield first
        first.prompt = mutation
        yield second

    records = plan_observed_requests(
        prompt_stream(),
        ["model-a"],
        [1],
        endpoint_type="mock",
    )

    assert [record.prompt for record in records] == [
        "original prompt text",
        "second prompt text",
    ]
    assert mutation not in "".join(record.model_dump_json() for record in records)


def test_counterfactual_planner_snapshots_each_intervention_as_it_is_consumed() -> None:
    prompt = _prompt("prompt-a")
    first = _intervention(
        prompt,
        intervention_id="int-a",
        counterfactual_prompt="original counterfactual text",
    )
    second = _intervention(
        prompt,
        intervention_id="int-b",
        counterfactual_prompt="second counterfactual text",
    )
    mutation = "generator-mutated-intervention-secret"

    def intervention_stream():
        yield first
        first.counterfactual_prompt = mutation
        yield second

    records = plan_counterfactual_requests(
        {prompt.prompt_id: prompt},
        intervention_stream(),
        ["model-a"],
        [1],
        endpoint_type="mock",
    )

    assert [record.prompt for record in records] == [
        "original counterfactual text",
        "second counterfactual text",
    ]
    assert mutation not in "".join(record.model_dump_json() for record in records)


def test_counterfactual_planner_snapshots_prompt_mapping_once_without_get() -> None:
    prompt = _prompt("prompt-a")
    secret = "prompt-mapping-get-secret"

    class ItemsOnlyPromptMapping(Mapping[str, PromptRecord]):
        def __init__(self) -> None:
            self.items_calls = 0
            self.get_calls = 0

        def __getitem__(self, key: str) -> PromptRecord:
            return prompt

        def __iter__(self) -> Iterator[str]:
            return iter((prompt.prompt_id,))

        def __len__(self) -> int:
            return 1

        def items(self):  # type: ignore[no-untyped-def]
            self.items_calls += 1
            return ((prompt.prompt_id, prompt),)

        def get(self, key: str, default: object = None) -> PromptRecord | object:
            self.get_calls += 1
            raise RuntimeError(secret)

    prompts = ItemsOnlyPromptMapping()
    records = plan_counterfactual_requests(
        prompts,
        [_intervention(prompt)],
        ["model-a"],
        [1],
        endpoint_type="mock",
    )

    assert len(records) == 1
    assert prompts.items_calls == 1
    assert prompts.get_calls == 0
    assert secret not in records[0].model_dump_json()


@pytest.mark.parametrize("failure_mode", ["items_error", "items_overflow"])
def test_counterfactual_planner_safely_bounds_prompt_mapping_items(
    failure_mode: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limit = 2
    monkeypatch.setattr(request_planner, "MAX_GENERATION_AXIS_ITEMS", limit)
    prompt = _prompt("prompt-a")
    secret = "prompt-mapping-items-secret"
    guarded = GuardedInfiniteIterator(
        lambda index: (f"prompt-{index}", _prompt(f"prompt-{index}")),
        maximum_reads=limit + 1,
    )

    class ControlledItemsMapping(Mapping[str, PromptRecord]):
        def __init__(self) -> None:
            self.items_calls = 0

        def __getitem__(self, key: str) -> PromptRecord:
            return prompt

        def __iter__(self) -> Iterator[str]:
            return iter((prompt.prompt_id,))

        def __len__(self) -> int:
            return 1

        def items(self):  # type: ignore[no-untyped-def]
            self.items_calls += 1
            if failure_mode == "items_error":
                raise RuntimeError(secret)
            return guarded

    prompts = ControlledItemsMapping()
    with pytest.raises(SecAwareError) as exc_info:
        plan_counterfactual_requests(
            prompts,
            [_intervention(prompt)],
            ["model-a"],
            [1],
            endpoint_type="mock",
        )

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert prompts.items_calls == 1
    if failure_mode == "items_overflow":
        assert guarded.reads == limit + 1
    rendered = (
        str(exc_info.value),
        "".join(traceback.format_exception(exc_info.value)),
        json.dumps(exc_info.value.to_dict(), sort_keys=True),
    )
    for hidden_text in (secret, "RuntimeError"):
        assert all(hidden_text not in surface for surface in rendered)


@pytest.mark.parametrize("source", ["observed_prompt", "mapped_prompt", "intervention"])
def test_planner_revalidates_forged_input_models(source: str) -> None:
    secret = "forged-planner-model-secret"
    prompt = _prompt("prompt-a")

    with pytest.raises(SecAwareError) as exc_info:
        if source == "observed_prompt":
            forged_prompt = prompt.model_copy(update={"split": secret})
            plan_observed_requests(
                [forged_prompt],
                ["model-a"],
                [1],
                endpoint_type="mock",
            )
        elif source == "mapped_prompt":
            forged_prompt = prompt.model_copy(update={"split": secret})
            plan_counterfactual_requests(
                {prompt.prompt_id: forged_prompt},
                [_intervention(prompt)],
                ["model-a"],
                [1],
                endpoint_type="mock",
            )
        else:
            forged_intervention = _intervention(prompt).model_copy(update={"factor_type": secret})
            plan_counterfactual_requests(
                {prompt.prompt_id: prompt},
                [forged_intervention],
                ["model-a"],
                [1],
                endpoint_type="mock",
            )

    assert exc_info.value.code is ErrorCode.CONTRACT
    rendered = (
        str(exc_info.value),
        "".join(traceback.format_exception(exc_info.value)),
        json.dumps(exc_info.value.to_dict(), sort_keys=True),
    )
    for hidden_text in (secret, "ValidationError"):
        assert all(hidden_text not in surface for surface in rendered)

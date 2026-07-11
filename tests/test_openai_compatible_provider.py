from dataclasses import FrozenInstanceError
import inspect
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace
import sys
import traceback

import pytest
from pydantic import ValidationError

from secaware.config import AppConfig, OpenAICompatibleConfig, load_config
from secaware.errors import ErrorCode, SecAwareError
from secaware.generation.openai_compatible_provider import (
    OpenAICompatibleGenerationResult,
    OpenAICompatibleProvider,
    create_openai_compatible_provider,
)
from secaware.generation.request_planner import plan_observed_requests
from secaware.io.jsonl import write_jsonl
from secaware.pipeline.preflight import run_preflight
from secaware.schema.common import SCHEMA_VERSION
from secaware.schema.generation import (
    GenerationAttemptRecord,
    GenerationParameters,
    GenerationProvenance,
    GenerationRequestRecord,
)
from secaware.schema.records import PromptRecord


_BASE_URL = "https://provider.invalid/v1"
_ENV_NAME = "SECAWARE_TEST_OPENAI_KEY"
_API_KEY = "provider-api-key-secret"
_PROMPT = "Return a path helper and preserve this sensitive prompt exactly."
_SYSTEM = "Return code only."
_CODE = "```python\ndef helper(path):\n    return path\n```"


def _validation_surfaces(error: ValidationError) -> tuple[str, ...]:
    return (
        str(error),
        "".join(traceback.format_exception(error)),
        json.dumps(error.errors(), default=str, sort_keys=True),
        error.json(),
    )


def _error_surfaces(error: SecAwareError) -> tuple[str, ...]:
    return (
        str(error),
        "".join(traceback.format_exception(error)),
        json.dumps(error.to_dict(), default=str, sort_keys=True),
    )


def _secaware_traceback_locals(error: SecAwareError) -> str:
    snapshots: list[str] = []
    current = error.__traceback__
    while current is not None:
        filename = current.tb_frame.f_code.co_filename.replace("\\", "/")
        if "/src/secaware/" in filename:
            snapshots.append(repr(current.tb_frame.f_locals))
        current = current.tb_next
    return "\n".join(snapshots)


def _assert_safe_validation_error(error: ValidationError, *hidden: str) -> None:
    assert error.__cause__ is None
    assert error.__context__ is None
    structured = error.errors()
    assert len(structured) == 1
    assert structured[0]["loc"] == ()
    assert structured[0].get("input") is None
    assert "ctx" not in structured[0]
    retained = _secaware_traceback_locals(error)  # type: ignore[arg-type]
    for value in hidden:
        if not value or value.isspace():
            continue
        assert all(value not in surface for surface in _validation_surfaces(error))
        assert value not in retained


def _assert_safe_provider_error(error: SecAwareError, *hidden: str) -> None:
    assert error.__cause__ is None
    assert error.__context__ is None
    retained = _secaware_traceback_locals(error)
    for value in (_API_KEY, _BASE_URL, _ENV_NAME, _PROMPT, _CODE, *hidden):
        if not value or value.isspace():
            continue
        assert all(value not in surface for surface in _error_surfaces(error))
        assert value not in retained


def _config(**overrides: object) -> OpenAICompatibleConfig:
    values: dict[str, object] = {
        "base_url": _BASE_URL,
        "api_key_env": _ENV_NAME,
        "timeout_seconds": 12.5,
        "max_attempts": 3,
        "initial_backoff_seconds": 0.25,
        "max_backoff_seconds": 0.5,
    }
    values.update(overrides)
    return OpenAICompatibleConfig.model_validate(values)


def _request(
    *,
    endpoint_type: str = "chat_completions",
    system_template: str = _SYSTEM,
    parameters: dict[str, object] | None = None,
    include_default_max_tokens: bool = True,
) -> GenerationRequestRecord:
    prompt = PromptRecord(
        prompt_id="prompt-api",
        split="confirm",
        language="python",
        task_family="path_handling",
        cwe="CWE-22",
        prompt=_PROMPT,
    )
    parameter_values: dict[str, object] = {
        "temperature": 0.2,
        "seed": 7,
        "n": 1,
    }
    if include_default_max_tokens:
        parameter_values["max_tokens"] = 128
    parameter_values.update(parameters or {})
    return plan_observed_requests(
        [prompt],
        ["org/model-api"],
        [7],
        endpoint_type=endpoint_type,  # type: ignore[arg-type]
        parameters=GenerationParameters(values=parameter_values),
        system_template=system_template,
        system_template_version="system-v1",
    )[0]


def _response(
    *,
    code: object = _CODE,
    finish_reason: object = "stop",
    usage: object = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(content=code),
                finish_reason=finish_reason,
            )
        ],
        usage=usage,
    )


class FakeCompletions:
    def __init__(self, outcomes: list[object]) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[dict[str, object]] = []

    def create(self, **kwargs: object) -> object:
        self.calls.append(kwargs)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class FakeClient:
    def __init__(self, outcomes: list[object]) -> None:
        self.completions = FakeCompletions(outcomes)
        self.chat = SimpleNamespace(completions=self.completions)


class StatusFailure(Exception):
    def __init__(self, status_code: int) -> None:
        super().__init__("raw provider response body secret")
        self.status_code = status_code
        self.response = SimpleNamespace(
            headers={"Authorization": f"Bearer {_API_KEY}"},
            text="raw provider response body secret",
        )


class APITimeoutError(Exception):
    pass


class APIConnectionError(Exception):
    pass


@pytest.mark.parametrize(
    "entrypoint",
    ["constructor", "model_validate", "model_validate_json", "model_validate_strings"],
)
@pytest.mark.parametrize("forbidden_field", ["api_key", "token", "headers"])
def test_openai_config_rejects_secret_fields_on_all_public_validation_surfaces(
    entrypoint: str,
    forbidden_field: str,
) -> None:
    secret = f"forbidden-{forbidden_field}-material"
    payload = {
        "base_url": _BASE_URL,
        forbidden_field: {"Authorization": secret} if forbidden_field == "headers" else secret,
    }

    with pytest.raises(ValidationError) as exc_info:
        if entrypoint == "constructor":
            OpenAICompatibleConfig(**payload)
        elif entrypoint == "model_validate":
            OpenAICompatibleConfig.model_validate(payload)
        elif entrypoint == "model_validate_json":
            OpenAICompatibleConfig.model_validate_json(json.dumps(payload))
        else:
            OpenAICompatibleConfig.model_validate_strings(payload)

    _assert_safe_validation_error(
        exc_info.value,
        forbidden_field,
        secret,
        _BASE_URL,
    )


@pytest.mark.parametrize(
    "base_url",
    [
        "provider.invalid/v1",
        "ftp://provider.invalid/v1",
        "https:///v1",
        "https://user:password@provider.invalid/v1",
        "https://provider.invalid/v1?",
        "https://provider.invalid/v1?api_key=secret-query",
        "https://provider.invalid/v1#",
        "https://provider.invalid/v1#secret-fragment",
        "https://provider.invalid/\x7fsecret-control",
    ],
)
def test_openai_config_requires_safe_absolute_http_url(base_url: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        _config(base_url=base_url)

    _assert_safe_validation_error(exc_info.value, base_url)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("timeout_seconds", 0),
        ("timeout_seconds", float("inf")),
        ("timeout_seconds", 100_000),
        ("max_attempts", 0),
        ("max_attempts", 11),
        ("initial_backoff_seconds", -0.1),
        ("initial_backoff_seconds", float("nan")),
        ("initial_backoff_seconds", 301),
        ("max_backoff_seconds", -0.1),
        ("max_backoff_seconds", float("inf")),
        ("max_backoff_seconds", 3_601),
    ],
)
def test_openai_config_numeric_controls_are_finite_and_bounded(
    field: str,
    value: object,
) -> None:
    with pytest.raises(ValidationError):
        _config(**{field: value})


def test_openai_config_rejects_backoff_cap_below_initial_delay() -> None:
    with pytest.raises(ValidationError):
        _config(initial_backoff_seconds=2.0, max_backoff_seconds=1.0)


@pytest.mark.parametrize(
    "api_key_env",
    ["", "9INVALID", "INVALID-NAME", "INVALID NAME", "A" * 129],
)
def test_openai_config_requires_a_safe_environment_variable_name(api_key_env: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        _config(api_key_env=api_key_env)

    _assert_safe_validation_error(exc_info.value, api_key_env)


def test_openai_config_repr_does_not_reveal_endpoint_or_environment_name() -> None:
    config = _config()

    rendered = repr(config)

    assert _BASE_URL not in rendered
    assert _ENV_NAME not in rendered
    assert _API_KEY not in rendered


def test_generation_config_accepts_new_provider_without_removing_legacy_api() -> None:
    base = {"run": {"name": "api"}, "data": {"prompts_path": "prompts.jsonl"}}

    compatible = AppConfig.model_validate(
        {
            **base,
            "generation": {
                "provider": "openai_compatible",
                "openai_compatible": _config().model_dump(mode="python"),
            },
        }
    )
    legacy = AppConfig.model_validate({**base, "generation": {"provider": "api"}})

    assert compatible.generation.provider == "openai_compatible"
    assert isinstance(compatible.generation.openai_compatible, OpenAICompatibleConfig)
    assert legacy.generation.provider == "api"


def test_loading_invalid_openai_config_never_echoes_yaml_secrets(tmp_path: Path) -> None:
    secret = "yaml-api-key-material"
    path = tmp_path / "private-config.yaml"
    path.write_text(
        "run:\n  name: private\n"
        "data:\n  prompts_path: prompts.jsonl\n"
        "generation:\n  provider: openai_compatible\n"
        "  openai_compatible:\n"
        f"    base_url: {_BASE_URL}\n"
        f"    api_key: {secret}\n",
        encoding="utf-8",
    )

    with pytest.raises(SecAwareError) as exc_info:
        load_config(path)

    assert exc_info.value.code is ErrorCode.CONFIG
    _assert_safe_provider_error(exc_info.value, secret, str(path))
    assert secret not in _secaware_traceback_locals(exc_info.value)


@pytest.mark.parametrize(
    "entrypoint",
    ["constructor", "model_validate", "model_validate_json", "model_validate_strings"],
)
def test_attempt_record_is_strict_frozen_and_safely_validated(entrypoint: str) -> None:
    secret = "invalid-attempt-request-id-secret"
    payload = {
        "schema_version": SCHEMA_VERSION,
        "request_id": secret,
        "attempt": 1,
        "outcome": "failure",
        "error_code": int(ErrorCode.API_INVALID_RESPONSE),
        "retryable": False,
        "backoff_seconds": 0.0,
    }

    with pytest.raises(ValidationError) as exc_info:
        if entrypoint == "constructor":
            GenerationAttemptRecord(**payload)
        elif entrypoint == "model_validate":
            GenerationAttemptRecord.model_validate(payload)
        elif entrypoint == "model_validate_json":
            GenerationAttemptRecord.model_validate_json(json.dumps(payload))
        else:
            GenerationAttemptRecord.model_validate_strings(payload)

    _assert_safe_validation_error(exc_info.value, secret)

    valid = GenerationAttemptRecord(
        schema_version=SCHEMA_VERSION,
        request_id="req_" + "a" * 64,
        attempt=1,
        outcome="success",
        error_code=None,
        retryable=False,
        backoff_seconds=0.0,
    )
    with pytest.raises(ValidationError):
        valid.attempt = 2


def _write_prompt_config(
    tmp_path: Path,
    *,
    provider: str,
    include_openai_config: bool,
) -> AppConfig:
    prompts_path = tmp_path / "prompts.jsonl"
    write_jsonl(
        prompts_path,
        [
            PromptRecord(
                prompt_id="prompt-preflight",
                split="discover",
                language="python",
                task_family="path_handling",
                cwe="CWE-22",
                prompt="Write a safe path helper.",
            )
        ],
    )
    generation: dict[str, object] = {
        "provider": provider,
        "models": ["model-api"],
        "seeds": [7],
    }
    if include_openai_config:
        generation["openai_compatible"] = _config().model_dump(mode="python")
    return AppConfig.model_validate(
        {
            "run": {"name": "preflight", "output_dir": str(tmp_path / "run")},
            "data": {"prompts_path": str(prompts_path)},
            "generation": generation,
        }
    )


def test_preflight_requires_openai_subconfig_without_echoing_configuration(
    tmp_path: Path,
) -> None:
    config = _write_prompt_config(
        tmp_path,
        provider="openai_compatible",
        include_openai_config=False,
    )

    with pytest.raises(SecAwareError) as exc_info:
        run_preflight(config)

    assert exc_info.value.code is ErrorCode.CONFIG
    _assert_safe_provider_error(exc_info.value)


@pytest.mark.parametrize("credential", [None, "", "   "])
def test_preflight_requires_nonempty_openai_credential_only_when_selected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    credential: str | None,
) -> None:
    config = _write_prompt_config(
        tmp_path,
        provider="openai_compatible",
        include_openai_config=True,
    )
    if credential is None:
        monkeypatch.delenv(_ENV_NAME, raising=False)
    else:
        monkeypatch.setenv(_ENV_NAME, credential)

    with pytest.raises(SecAwareError) as exc_info:
        run_preflight(config)

    assert exc_info.value.code is ErrorCode.API_AUTH
    _assert_safe_provider_error(exc_info.value, credential or "missing")


def test_preflight_checks_credentials_before_retaining_prompt_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompt_secret = "preflight-prompt-frame-sentinel"
    config = _write_prompt_config(
        tmp_path,
        provider="openai_compatible",
        include_openai_config=True,
    )
    write_jsonl(
        config.data.prompts_path,
        [
            PromptRecord(
                prompt_id="prompt-sensitive-preflight",
                split="discover",
                language="python",
                task_family="path_handling",
                cwe="CWE-22",
                prompt=prompt_secret,
            )
        ],
    )
    monkeypatch.delenv(_ENV_NAME, raising=False)

    with pytest.raises(SecAwareError) as exc_info:
        run_preflight(config)

    assert exc_info.value.code is ErrorCode.API_AUTH
    _assert_safe_provider_error(
        exc_info.value,
        prompt_secret,
        _API_KEY,
        _BASE_URL,
    )


def test_preflight_does_not_require_openai_credentials_for_other_providers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _write_prompt_config(
        tmp_path,
        provider="mock",
        include_openai_config=True,
    )
    monkeypatch.delenv(_ENV_NAME, raising=False)

    report = run_preflight(config)

    assert report.model_count == 1


def test_provider_sends_only_canonical_chat_completion_payload_and_preserves_code() -> None:
    request = _request()
    usage = SimpleNamespace(prompt_tokens=11, completion_tokens=13, total_tokens=24)
    client = FakeClient([_response(usage=usage)])
    provider = OpenAICompatibleProvider(_config(), client=client, sleeper=lambda _: None)

    result = provider.generate(request, system_template=_SYSTEM)

    assert client.completions.calls == [
        {
            "model": "org/model-api",
            "messages": [
                {"role": "system", "content": _SYSTEM},
                {"role": "user", "content": _PROMPT},
            ],
            "temperature": 0.2,
            "max_tokens": 128,
            "seed": 7,
            "n": 1,
        }
    ]
    assert isinstance(result, OpenAICompatibleGenerationResult)
    assert result.code == _CODE
    assert isinstance(result.provenance, GenerationProvenance)
    assert result.provenance.producer == "openai_compatible"
    assert result.provenance.producer_version == "chat_completions-v1"
    assert result.attempts == (
        GenerationAttemptRecord(
            schema_version=SCHEMA_VERSION,
            request_id=request.request_id,
            attempt=1,
            outcome="success",
            error_code=None,
            retryable=False,
            backoff_seconds=0.0,
        ),
    )
    assert _CODE not in repr(result)
    assert request.request_id not in repr(result)
    with pytest.raises(FrozenInstanceError):
        result.code = "mutated"  # type: ignore[misc]


def test_compatibility_parameters_use_extra_body_and_translate_max_output_tokens() -> None:
    class ExplicitCompletions:
        def __init__(self) -> None:
            self.call: dict[str, object] | None = None

        def create(
            self,
            *,
            model: str,
            messages: list[dict[str, str]],
            temperature: float,
            seed: int,
            n: int,
            extra_body: dict[str, object],
        ) -> object:
            self.call = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "seed": seed,
                "n": n,
                "extra_body": extra_body,
            }
            return _response()

    completions = ExplicitCompletions()
    client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    provider = OpenAICompatibleProvider(_config(), client=client, sleeper=lambda _: None)

    result = provider.generate(
        _request(
            include_default_max_tokens=False,
            parameters={
                "max_output_tokens": 256,
                "reasoning_effort": "medium",
                "verbosity": "low",
            },
        ),
        system_template=_SYSTEM,
    )

    assert result.code == _CODE
    assert completions.call == {
        "model": "org/model-api",
        "messages": [
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": _PROMPT},
        ],
        "temperature": 0.2,
        "seed": 7,
        "n": 1,
        "extra_body": {
            "max_completion_tokens": 256,
            "reasoning_effort": "medium",
            "verbosity": "low",
        },
    }


def test_max_completion_tokens_is_sent_through_extra_body() -> None:
    client = FakeClient([_response()])
    provider = OpenAICompatibleProvider(_config(), client=client, sleeper=lambda _: None)

    provider.generate(
        _request(
            include_default_max_tokens=False,
            parameters={"max_completion_tokens": 192},
        ),
        system_template=_SYSTEM,
    )

    call = client.completions.calls[0]
    assert call["extra_body"] == {"max_completion_tokens": 192}
    assert "max_completion_tokens" not in {
        key for key in call if key != "extra_body"
    }


def test_translated_payload_matches_installed_official_sdk_signature() -> None:
    pytest.importorskip("openai")
    from openai.resources.chat.completions import Completions

    client = FakeClient([_response()])
    provider = OpenAICompatibleProvider(_config(), client=client, sleeper=lambda _: None)
    provider.generate(
        _request(
            include_default_max_tokens=False,
            parameters={
                "max_output_tokens": 64,
                "reasoning_effort": "low",
                "verbosity": "high",
            },
        ),
        system_template=_SYSTEM,
    )

    supported = set(inspect.signature(Completions.create).parameters)
    assert set(client.completions.calls[0]) <= supported
    assert "max_output_tokens" not in client.completions.calls[0]


@pytest.mark.parametrize(
    "parameters",
    [
        {"max_tokens": 64, "max_completion_tokens": 64},
        {"max_tokens": 64, "max_output_tokens": 64},
        {"max_completion_tokens": 64, "max_output_tokens": 64},
        {
            "max_tokens": 64,
            "max_completion_tokens": 64,
            "max_output_tokens": 64,
        },
    ],
)
def test_conflicting_max_token_parameters_fail_before_client_call(
    parameters: dict[str, object],
) -> None:
    client = FakeClient([_response()])
    provider = OpenAICompatibleProvider(_config(), client=client, sleeper=lambda _: None)

    with pytest.raises(SecAwareError) as exc_info:
        provider.generate(
            _request(
                include_default_max_tokens=False,
                parameters=parameters,
            ),
            system_template=_SYSTEM,
        )

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert client.completions.calls == []
    _assert_safe_provider_error(exc_info.value)


def test_empty_system_template_is_not_sent() -> None:
    request = _request(system_template="")
    client = FakeClient([_response()])
    provider = OpenAICompatibleProvider(_config(), client=client, sleeper=lambda _: None)

    provider.generate(request)

    assert client.completions.calls[0]["messages"] == [
        {"role": "user", "content": _PROMPT}
    ]


def test_optional_usage_may_be_absent_from_a_valid_response() -> None:
    response = SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(content=_CODE),
                finish_reason="stop",
            )
        ]
    )
    client = FakeClient([response])
    provider = OpenAICompatibleProvider(_config(), client=client, sleeper=lambda _: None)

    result = provider.generate(_request(), system_template=_SYSTEM)

    assert result.code == _CODE


def test_provider_constructor_clears_inputs_after_invalid_config() -> None:
    config_sentinel = "constructor-invalid-config-sentinel"
    client_sentinel = "constructor-invalid-client-sentinel"
    sleeper_sentinel = "constructor-invalid-sleeper-sentinel"

    class HostileClient:
        def __repr__(self) -> str:
            return client_sentinel

    class HostileSleeper:
        def __call__(self, delay: float) -> None:
            del delay

        def __repr__(self) -> str:
            return sleeper_sentinel

    raw_config = {
        "base_url": f"https://{config_sentinel}.invalid/v1",
        "api_key": config_sentinel,
    }
    with pytest.raises(SecAwareError) as exc_info:
        OpenAICompatibleProvider(
            raw_config,  # type: ignore[arg-type]
            client=HostileClient(),
            sleeper=HostileSleeper(),
        )

    assert exc_info.value.code is ErrorCode.CONFIG
    _assert_safe_provider_error(
        exc_info.value,
        config_sentinel,
        client_sentinel,
        sleeper_sentinel,
        raw_config["base_url"],
    )


def test_provider_constructor_clears_client_and_hostile_noncallable_sleeper() -> None:
    client_sentinel = "constructor-client-frame-sentinel"
    sleeper_sentinel = "constructor-sleeper-frame-sentinel"

    class HostileValue:
        def __init__(self, rendered: str) -> None:
            self.rendered = rendered

        def __repr__(self) -> str:
            return self.rendered

    with pytest.raises(SecAwareError) as exc_info:
        OpenAICompatibleProvider(
            _config(),
            client=HostileValue(client_sentinel),
            sleeper=HostileValue(sleeper_sentinel),  # type: ignore[arg-type]
        )

    assert exc_info.value.code is ErrorCode.CONFIG
    _assert_safe_provider_error(
        exc_info.value,
        client_sentinel,
        sleeper_sentinel,
    )


def test_provider_factory_uses_official_sdk_with_retries_disabled_and_keeps_no_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    client = FakeClient([_response()])
    fake_openai = ModuleType("openai")

    def openai_factory(**kwargs: object) -> FakeClient:
        captured.update(kwargs)
        return client

    fake_openai.OpenAI = openai_factory  # type: ignore[attr-defined]
    fake_openai.__version__ = "2.3.4"
    monkeypatch.setitem(sys.modules, "openai", fake_openai)

    provider = create_openai_compatible_provider(
        _config(),
        environ={_ENV_NAME: _API_KEY},
        sleeper=lambda _: None,
    )

    assert captured == {
        "api_key": _API_KEY,
        "base_url": _BASE_URL,
        "timeout": 12.5,
        "max_retries": 0,
    }
    assert not hasattr(provider, "_api_key")
    assert _API_KEY not in repr(provider)
    assert _BASE_URL not in repr(provider)
    provider.generate(_request(), system_template=_SYSTEM)


def test_factory_maps_missing_key_to_safe_auth_error() -> None:
    with pytest.raises(SecAwareError) as exc_info:
        create_openai_compatible_provider(_config(), environ={})

    assert exc_info.value.code is ErrorCode.API_AUTH
    _assert_safe_provider_error(exc_info.value)


def test_factory_rejects_raw_config_mapping_without_retaining_inputs() -> None:
    sentinel = "invalid-factory-config-frame-sentinel"
    raw_config = {
        "base_url": f"https://{sentinel}.invalid/v1",
        "api_key": sentinel,
        "wrapper": {"token": sentinel},
    }

    with pytest.raises(SecAwareError) as exc_info:
        create_openai_compatible_provider(
            raw_config,  # type: ignore[arg-type]
            environ={_ENV_NAME: _API_KEY},
        )

    assert exc_info.value.code is ErrorCode.CONFIG
    _assert_safe_provider_error(
        exc_info.value,
        sentinel,
        raw_config["base_url"],
        _API_KEY,
        _BASE_URL,
    )


def test_factory_maps_missing_sdk_to_safe_config_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "openai", None)

    with pytest.raises(SecAwareError) as exc_info:
        create_openai_compatible_provider(
            _config(),
            environ={_ENV_NAME: _API_KEY},
        )

    assert exc_info.value.code is ErrorCode.CONFIG
    _assert_safe_provider_error(exc_info.value, "ModuleNotFoundError")
    retained = _secaware_traceback_locals(exc_info.value)
    for value in (_API_KEY, _BASE_URL, _ENV_NAME):
        assert value not in retained


def test_factory_does_not_retain_secrets_when_sdk_client_creation_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_openai = ModuleType("openai")

    def failing_factory(**kwargs: object) -> object:
        del kwargs
        raise RuntimeError("hostile-sdk-constructor-secret")

    fake_openai.OpenAI = failing_factory  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "openai", fake_openai)

    with pytest.raises(SecAwareError) as exc_info:
        create_openai_compatible_provider(
            _config(),
            environ={_ENV_NAME: _API_KEY},
        )

    assert exc_info.value.code is ErrorCode.CONFIG
    _assert_safe_provider_error(exc_info.value, "hostile-sdk-constructor-secret")
    retained = _secaware_traceback_locals(exc_info.value)
    for value in (_API_KEY, _BASE_URL, _ENV_NAME, "hostile-sdk-constructor-secret"):
        assert value not in retained


@pytest.mark.parametrize(
    ("failure", "expected_code"),
    [
        (StatusFailure(429), ErrorCode.API_RATE_LIMIT),
        (APITimeoutError("timeout body secret"), ErrorCode.API_TIMEOUT),
        (APIConnectionError("connection body secret"), ErrorCode.API_TIMEOUT),
        (TimeoutError("builtin timeout body secret"), ErrorCode.API_TIMEOUT),
        (ConnectionError("builtin connection body secret"), ErrorCode.API_TIMEOUT),
        (StatusFailure(408), ErrorCode.API_TIMEOUT),
        (StatusFailure(409), ErrorCode.API_INVALID_RESPONSE),
        (StatusFailure(500), ErrorCode.API_INVALID_RESPONSE),
        (StatusFailure(503), ErrorCode.API_INVALID_RESPONSE),
    ],
)
def test_retryable_failures_use_deterministic_backoff_and_success_journal(
    failure: Exception,
    expected_code: ErrorCode,
) -> None:
    request = _request()
    sleeps: list[float] = []
    client = FakeClient([failure, _response()])
    provider = OpenAICompatibleProvider(_config(), client=client, sleeper=sleeps.append)

    result = provider.generate(request, system_template=_SYSTEM)

    assert sleeps == [0.25]
    assert len(client.completions.calls) == 2
    assert [(item.attempt, item.outcome) for item in result.attempts] == [
        (1, "retry"),
        (2, "success"),
    ]
    assert result.attempts[0].error_code == int(expected_code)
    assert result.attempts[0].retryable is True
    assert result.attempts[0].backoff_seconds == 0.25


def test_backoff_is_exponential_and_capped_without_jitter() -> None:
    sleeps: list[float] = []
    client = FakeClient(
        [StatusFailure(500), StatusFailure(500), StatusFailure(500), _response()]
    )
    provider = OpenAICompatibleProvider(
        _config(max_attempts=4),
        client=client,
        sleeper=sleeps.append,
    )

    result = provider.generate(_request(), system_template=_SYSTEM)

    assert sleeps == [0.25, 0.5, 0.5]
    assert [attempt.backoff_seconds for attempt in result.attempts] == [
        0.25,
        0.5,
        0.5,
        0.0,
    ]


def test_each_retry_rebuilds_the_canonical_payload_after_client_mutation() -> None:
    mutation = "client-mutated-retry-payload-secret"

    class MutatingCompletions:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        def create(self, **kwargs: object) -> object:
            self.calls.append(json.loads(json.dumps(kwargs)))
            if len(self.calls) == 1:
                messages = kwargs["messages"]
                stop = kwargs["stop"]
                assert isinstance(messages, list)
                assert isinstance(stop, list)
                messages[0]["content"] = mutation
                stop.append(mutation)
                raise StatusFailure(429)
            return _response()

    completions = MutatingCompletions()
    client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    provider = OpenAICompatibleProvider(_config(), client=client, sleeper=lambda _: None)

    provider.generate(
        _request(parameters={"stop": ["END"]}),
        system_template=_SYSTEM,
    )

    assert len(completions.calls) == 2
    assert completions.calls[1]["messages"] == [
        {"role": "system", "content": _SYSTEM},
        {"role": "user", "content": _PROMPT},
    ]
    assert completions.calls[1]["stop"] == ["END"]
    assert mutation not in json.dumps(completions.calls[1], sort_keys=True)


@pytest.mark.parametrize(
    ("status_code", "expected_code"),
    [
        (400, ErrorCode.API_INVALID_RESPONSE),
        (401, ErrorCode.API_AUTH),
        (403, ErrorCode.API_AUTH),
        (404, ErrorCode.API_INVALID_RESPONSE),
        (422, ErrorCode.API_INVALID_RESPONSE),
    ],
)
def test_nonretryable_http_failures_are_mapped_without_retry(
    status_code: int,
    expected_code: ErrorCode,
) -> None:
    client = FakeClient([StatusFailure(status_code)])
    sleeps: list[float] = []
    provider = OpenAICompatibleProvider(_config(), client=client, sleeper=sleeps.append)

    with pytest.raises(SecAwareError) as exc_info:
        provider.generate(_request(), system_template=_SYSTEM)

    assert exc_info.value.code is expected_code
    assert exc_info.value.retryable is False
    assert len(client.completions.calls) == 1
    assert sleeps == []
    _assert_safe_provider_error(exc_info.value, "raw provider response body secret")


def test_retry_exhaustion_returns_safe_attempt_summaries_without_request_id() -> None:
    request = _request()
    client = FakeClient([StatusFailure(429), StatusFailure(429), StatusFailure(429)])
    sleeps: list[float] = []
    provider = OpenAICompatibleProvider(_config(), client=client, sleeper=sleeps.append)

    with pytest.raises(SecAwareError) as exc_info:
        provider.generate(request, system_template=_SYSTEM)

    error = exc_info.value
    assert error.code is ErrorCode.API_RETRIES_EXHAUSTED
    assert error.retryable is False
    assert sleeps == [0.25, 0.5]
    assert error.details == {
        "attempts": [
            {
                "attempt": 1,
                "outcome": "retry",
                "error_code": int(ErrorCode.API_RATE_LIMIT),
                "retryable": True,
                "backoff_seconds": 0.25,
            },
            {
                "attempt": 2,
                "outcome": "retry",
                "error_code": int(ErrorCode.API_RATE_LIMIT),
                "retryable": True,
                "backoff_seconds": 0.5,
            },
            {
                "attempt": 3,
                "outcome": "failure",
                "error_code": int(ErrorCode.API_RATE_LIMIT),
                "retryable": True,
                "backoff_seconds": 0.0,
            },
        ]
    }
    assert request.request_id not in json.dumps(error.to_dict(), sort_keys=True)
    _assert_safe_provider_error(error, "raw provider response body secret")


@pytest.mark.parametrize(
    "response",
    [
        SimpleNamespace(choices=[], usage=None),
        SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content="malformed-first-body-secret"),
                    finish_reason="stop",
                ),
                SimpleNamespace(
                    message=SimpleNamespace(content="malformed-second-body-secret"),
                    finish_reason="stop",
                ),
            ],
            usage=None,
        ),
        _response(code=None),
        _response(code=123),
        _response(code=""),
        _response(code="   "),
        _response(finish_reason=None),
        _response(finish_reason="malformed-finish-reason-secret"),
        _response(
            usage=SimpleNamespace(prompt_tokens=-1, completion_tokens=1, total_tokens=0)
        ),
        _response(
            usage=SimpleNamespace(prompt_tokens=True, completion_tokens=1, total_tokens=2)
        ),
        _response(
            usage=SimpleNamespace(prompt_tokens=1.5, completion_tokens=1, total_tokens=2)
        ),
        _response(usage=SimpleNamespace(prompt_tokens=1, completion_tokens=1)),
    ],
)
def test_malformed_success_responses_are_rejected_without_retry(response: object) -> None:
    client = FakeClient([response])
    provider = OpenAICompatibleProvider(_config(), client=client, sleeper=lambda _: None)

    with pytest.raises(SecAwareError) as exc_info:
        provider.generate(_request(), system_template=_SYSTEM)

    assert exc_info.value.code is ErrorCode.API_INVALID_RESPONSE
    assert len(client.completions.calls) == 1
    _assert_safe_provider_error(
        exc_info.value,
        "malformed-first-body-secret",
        "malformed-second-body-secret",
        "malformed-finish-reason-secret",
    )


def test_hostile_client_exception_is_wrapped_without_rendering_it() -> None:
    secret = "hostile-client-exception-secret"

    class HostileFailure(Exception):
        def __str__(self) -> str:
            return secret

        def __repr__(self) -> str:
            return secret

    client = FakeClient([HostileFailure()])
    provider = OpenAICompatibleProvider(_config(), client=client, sleeper=lambda _: None)

    with pytest.raises(SecAwareError) as exc_info:
        provider.generate(_request(), system_template=_SYSTEM)

    assert exc_info.value.code is ErrorCode.API_INVALID_RESPONSE
    _assert_safe_provider_error(exc_info.value, secret, "HostileFailure")


def test_unknown_client_type_error_is_a_safe_remote_failure() -> None:
    secret = "unknown-client-type-error-sentinel"
    client = FakeClient([TypeError(secret)])
    provider = OpenAICompatibleProvider(_config(), client=client, sleeper=lambda _: None)

    with pytest.raises(SecAwareError) as exc_info:
        provider.generate(_request(), system_template=_SYSTEM)

    assert exc_info.value.code is ErrorCode.API_INVALID_RESPONSE
    assert len(client.completions.calls) == 1
    _assert_safe_provider_error(exc_info.value, secret, "TypeError")


def test_hostile_response_access_is_wrapped_without_leaking_body() -> None:
    secret = "hostile-response-access-secret"

    class HostileResponse:
        @property
        def choices(self) -> object:
            raise RuntimeError(secret)

    client = FakeClient([HostileResponse()])
    provider = OpenAICompatibleProvider(_config(), client=client, sleeper=lambda _: None)

    with pytest.raises(SecAwareError) as exc_info:
        provider.generate(_request(), system_template=_SYSTEM)

    assert exc_info.value.code is ErrorCode.API_INVALID_RESPONSE
    _assert_safe_provider_error(exc_info.value, secret, "RuntimeError")


def test_hostile_sleeper_exception_is_safely_wrapped() -> None:
    secret = "hostile-sleeper-secret"

    def sleeper(delay: float) -> None:
        del delay
        raise RuntimeError(secret)

    client = FakeClient([StatusFailure(429)])
    provider = OpenAICompatibleProvider(_config(), client=client, sleeper=sleeper)

    with pytest.raises(SecAwareError) as exc_info:
        provider.generate(_request(), system_template=_SYSTEM)

    assert exc_info.value.code is ErrorCode.API_INVALID_RESPONSE
    assert len(client.completions.calls) == 1
    _assert_safe_provider_error(exc_info.value, secret, "RuntimeError")


@pytest.mark.parametrize("forgery", ["prompt", "model", "extra"])
def test_provider_revalidates_model_copy_forged_requests(forgery: str) -> None:
    request = _request()
    secret = f"forged-{forgery}-request-secret"
    if forgery == "prompt":
        forged = request.model_copy(update={"prompt": secret})
    elif forgery == "model":
        forged = request.model_copy(update={"model_id": secret})
    else:
        forged = request.model_copy(update={"api_key": secret})
    client = FakeClient([_response()])
    provider = OpenAICompatibleProvider(_config(), client=client, sleeper=lambda _: None)

    with pytest.raises(SecAwareError) as exc_info:
        provider.generate(forged, system_template=_SYSTEM)

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert client.completions.calls == []
    _assert_safe_provider_error(exc_info.value, secret)


def test_provider_rejects_wrong_endpoint_system_hash_and_n_before_calling_client() -> None:
    cases = [
        (_request(endpoint_type="offline"), _SYSTEM),
        (_request(), "different system template secret"),
        (_request(parameters={"n": 2}), _SYSTEM),
    ]

    for request, system_template in cases:
        client = FakeClient([_response()])
        provider = OpenAICompatibleProvider(_config(), client=client, sleeper=lambda _: None)

        with pytest.raises(SecAwareError) as exc_info:
            provider.generate(request, system_template=system_template)

        assert exc_info.value.code is ErrorCode.CONTRACT
        assert client.completions.calls == []
        _assert_safe_provider_error(exc_info.value, system_template)


def test_api_optional_dependency_is_declared() -> None:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"

    contents = pyproject.read_text(encoding="utf-8")

    assert 'api = ["openai>=1.40,<3"]' in contents

from __future__ import annotations

import hashlib
import json
import sys
from types import SimpleNamespace

import pytest

from secaware.errors import ErrorCode, SecAwareError
from secaware.llm.structured_transport import (
    OpenAICompatibleStructuredTransport,
    StructuredLLMPolicy,
    canonical_request_bytes,
)


_BASE_URL = "https://provider.invalid/v1"
_TEMPLATE = "Return one JSON object."
_ENV_NAME = "SECAWARE_STRUCTURED_TEST_KEY"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _policy(**overrides: object) -> StructuredLLMPolicy:
    values: dict[str, object] = {
        "endpoint_sha256": _sha(_BASE_URL),
        "model_id": "test-model",
        "system_template_sha256": _sha(_TEMPLATE),
        "output_schema_sha256": _sha("facts-schema-v1"),
        "temperature": 0.0,
        "top_p": 1.0,
        "seed": 7,
        "timeout_seconds": 10.0,
        "max_attempts": 3,
        "max_response_bytes": 4096,
    }
    values.update(overrides)
    return StructuredLLMPolicy(**values)  # type: ignore[arg-type]


def _response(content: object = '{"facts":[]}', *, finish_reason: object = "stop") -> dict:
    return {
        "choices": [
            {
                "finish_reason": finish_reason,
                "message": {"content": content},
            }
        ]
    }


class _StatusFailure(Exception):
    def __init__(self, status_code: int, message: str = "provider failure") -> None:
        super().__init__(message)
        self.status_code = status_code


class _Completions:
    def __init__(self, outcomes: list[object]) -> None:
        self.outcomes = outcomes
        self.requests: list[dict[str, object]] = []

    def create(self, **kwargs: object) -> object:
        self.requests.append(kwargs)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class _Client:
    def __init__(self, outcomes: list[object]) -> None:
        self.completions = _Completions(outcomes)
        self.chat = type("Chat", (), {"completions": self.completions})()


def _transport(client: _Client, sleeps: list[float] | None = None):
    return OpenAICompatibleStructuredTransport(
        base_url=_BASE_URL,
        api_key_env=_ENV_NAME,
        system_template=_TEMPLATE,
        client=client,
        sleeper=(sleeps if sleeps is not None else []).append,
    )


def test_canonical_request_bytes_are_exact_deterministic_utf8_json() -> None:
    one = canonical_request_bytes({"z": "雪", "a": [1, True, None]})
    two = canonical_request_bytes({"a": [1, True, None], "z": "雪"})
    assert one == two == b'{"a":[1,true,null],"z":"\xe9\x9b\xaa"}'
    with pytest.raises((TypeError, ValueError)):
        canonical_request_bytes({"bad": float("nan")})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("endpoint_sha256", "x" * 64),
        ("model_id", " "),
        ("temperature", float("nan")),
        ("top_p", 0.0),
        ("seed", True),
        ("timeout_seconds", 0.0),
        ("max_attempts", 0),
        ("max_response_bytes", 0),
    ],
)
def test_structured_policy_rejects_invalid_runtime_values(field: str, value: object) -> None:
    with pytest.raises(ValueError):
        _policy(**{field: value})


def test_retry_resends_identical_locked_payload_and_uses_deterministic_backoff() -> None:
    sleeps: list[float] = []
    client = _Client([_StatusFailure(429), _response()])
    transport = _transport(client, sleeps)
    request = canonical_request_bytes({"prompt_text": "untrusted"})

    assert transport.complete(request, _policy()) == b'{"facts":[]}'
    assert client.completions.requests[0] == client.completions.requests[1]
    assert client.completions.requests[0]["messages"] is client.completions.requests[1]["messages"]
    assert sleeps == [1.0]


def test_transport_accepts_exactly_one_stopped_text_choice() -> None:
    transport = _transport(_Client([_response('{"ok":true}')]))
    assert transport.complete(b"{}", _policy()) == b'{"ok":true}'


@pytest.mark.parametrize(
    "response",
    [
        {"choices": []},
        {"choices": _response()["choices"] * 2},
        _response(finish_reason="length"),
        _response(content=[{"type": "text", "text": "{}"}]),
        {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"content": "{}", "tool_calls": [{"id": "call"}]},
                }
            ]
        },
        {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"content": "{}", "refusal": "cannot comply"},
                }
            ]
        },
    ],
)
def test_transport_rejects_non_single_text_stop_without_retry(response: object) -> None:
    client = _Client([response, _response()])
    with pytest.raises(SecAwareError) as exc_info:
        _transport(client).complete(b"{}", _policy())
    assert exc_info.value.code is ErrorCode.API_INVALID_RESPONSE
    assert len(client.completions.requests) == 1


def test_response_byte_limit_is_enforced_without_retry() -> None:
    client = _Client([_response("雪" * 4), _response()])
    with pytest.raises(SecAwareError):
        _transport(client).complete(b"{}", _policy(max_response_bytes=11))
    assert len(client.completions.requests) == 1


def test_transport_errors_retry_only_when_existing_classifier_marks_retryable() -> None:
    retrying = _Client([_StatusFailure(503), _response()])
    assert _transport(retrying).complete(b"{}", _policy()) == b'{"facts":[]}'
    denied = _Client([_StatusFailure(401), _response()])
    with pytest.raises(SecAwareError) as exc_info:
        _transport(denied).complete(b"{}", _policy())
    assert exc_info.value.code is ErrorCode.API_AUTH
    assert len(denied.completions.requests) == 1


def test_transport_repr_and_errors_do_not_expose_credentials(monkeypatch) -> None:
    secret = "structured-api-key-super-secret"
    monkeypatch.setenv(_ENV_NAME, secret)
    client = _Client([_StatusFailure(401, secret)])
    transport = _transport(client)
    assert secret not in repr(transport)
    with pytest.raises(SecAwareError) as exc_info:
        transport.complete(b"{}", _policy())
    assert secret not in str(exc_info.value)
    assert secret not in json.dumps(exc_info.value.to_dict())


def test_sdk_client_reads_api_key_only_from_configured_environment(monkeypatch) -> None:
    secret = "environment-only-structured-key"
    captured: dict[str, object] = {}

    def openai_factory(**kwargs: object) -> _Client:
        captured.update(kwargs)
        return _Client([_response()])

    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=openai_factory))
    transport = OpenAICompatibleStructuredTransport(
        base_url=_BASE_URL,
        api_key_env=_ENV_NAME,
        system_template=_TEMPLATE,
        environ={_ENV_NAME: secret, "OTHER_API_KEY": "must-not-be-read"},
        sleeper=lambda _seconds: None,
    )
    assert captured == {"api_key": secret, "base_url": _BASE_URL, "max_retries": 0}
    assert secret not in repr(transport)
    assert transport.complete(b"{}", _policy()) == b'{"facts":[]}'

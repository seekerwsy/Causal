from __future__ import annotations

import hashlib
import json
import sys
from collections import UserDict
from types import SimpleNamespace

import pytest

from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.common import MAX_MODEL_ID_CHARS
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
                "message": {"role": "assistant", "content": content},
            }
        ]
    }


class _StatusFailure(Exception):
    def __init__(self, status_code: int, message: str = "provider failure") -> None:
        super().__init__(message)
        self.status_code = status_code


def _exception_chain_text(error: BaseException) -> str:
    pending = [error]
    seen: set[int] = set()
    parts: list[str] = []
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        parts.extend((str(current), repr(current)))
        try:
            parts.append(repr(vars(current)))
        except Exception:
            parts.append("<unavailable exception state>")
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
    return "\n".join(parts)


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


def test_canonical_request_bytes_snapshots_nested_general_mappings() -> None:
    payload = UserDict(
        {
            "nested": UserDict({"snow": "雪", "flags": (True, False, None)}),
            "number": 7,
        }
    )
    expected = b'{"nested":{"flags":[true,false,null],"snow":"\xe9\x9b\xaa"},"number":7}'
    assert canonical_request_bytes(payload) == expected
    assert canonical_request_bytes(UserDict(reversed(list(payload.items())))) == expected


@pytest.mark.parametrize(
    "payload",
    [
        {"nested": {1: "integer-key", "1": "string-key"}},
        {"nested": {True: "boolean-key"}},
        {"set": {1, 2}},
        {"custom": SimpleNamespace(value=1)},
        {"infinite": float("inf")},
        {"negative_infinite": float("-inf")},
        {"surrogate": "\ud800"},
    ],
)
def test_canonical_request_bytes_rejects_values_outside_strict_json_domain(
    payload: object,
) -> None:
    with pytest.raises(ValueError, match="^structured request payload validation failed$"):
        canonical_request_bytes(payload)  # type: ignore[arg-type]


def test_canonical_request_mapping_iteration_failure_is_normalized_without_context() -> None:
    secret = "hostile-mapping-iteration-secret"

    class HostileMapping(UserDict):
        def items(self):
            raise RuntimeError(secret)

    with pytest.raises(ValueError) as exc_info:
        canonical_request_bytes(HostileMapping({"safe": 1}))

    assert str(exc_info.value) == "structured request payload validation failed"
    assert secret not in _exception_chain_text(exc_info.value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("endpoint_sha256", "x" * 64),
        ("model_id", " "),
        ("model_id", "model\x00id"),
        ("model_id", "model\nid"),
        ("model_id", "model\u202eid"),
        ("model_id", "m" * (MAX_MODEL_ID_CHARS + 1)),
        ("temperature", float("nan")),
        ("top_p", 0.0),
        ("seed", True),
        ("seed", -(2**63) - 1),
        ("seed", 2**63),
        ("enable_thinking", 0),
        ("timeout_seconds", 0.0),
        ("max_attempts", 0),
        ("max_response_bytes", 0),
    ],
)
def test_structured_policy_rejects_invalid_runtime_values(field: str, value: object) -> None:
    with pytest.raises(ValueError):
        _policy(**{field: value})


@pytest.mark.parametrize("seed", [-(2**63), -1, 0, 2**63 - 1])
def test_structured_policy_accepts_signed_64_bit_seed_boundaries(seed: int) -> None:
    assert _policy(seed=seed).seed == seed


def test_structured_policy_accepts_shared_model_id_maximum() -> None:
    model_id = "m" * MAX_MODEL_ID_CHARS
    assert _policy(model_id=model_id).model_id == model_id


def test_retry_resends_identical_locked_payload_and_uses_deterministic_backoff() -> None:
    sleeps: list[float] = []
    client = _Client([_StatusFailure(429), _response()])
    transport = _transport(client, sleeps)
    request = canonical_request_bytes({"prompt_text": "untrusted"})

    assert transport.complete(request, _policy()) == b'{"facts":[]}'
    assert client.completions.requests[0] == client.completions.requests[1]
    assert sleeps == [1.0]


def test_transport_sends_frozen_non_thinking_parameter_only_when_configured() -> None:
    without_switch = _Client([_response()])
    with_switch = _Client([_response()])

    assert _transport(without_switch).complete(b"{}", _policy()) == b'{"facts":[]}'
    assert _transport(with_switch).complete(
        b"{}",
        _policy(enable_thinking=False),
    ) == b'{"facts":[]}'

    assert "extra_body" not in without_switch.completions.requests[0]
    assert with_switch.completions.requests[0]["extra_body"] == {
        "enable_thinking": False,
    }


def test_retry_rebuilds_isolated_sdk_containers_after_client_mutation() -> None:
    class MutatingCompletions:
        def __init__(self) -> None:
            self.snapshots: list[bytes] = []
            self.calls = 0

        def create(self, **kwargs: object) -> object:
            self.calls += 1
            self.snapshots.append(canonical_request_bytes(kwargs))
            if self.calls == 1:
                messages = kwargs["messages"]
                assert isinstance(messages, list)
                messages[1]["content"] = "client-mutated-request"
                response_format = kwargs["response_format"]
                assert isinstance(response_format, dict)
                response_format["type"] = "client_mutated"
                raise _StatusFailure(429)
            return _response()

    completions = MutatingCompletions()
    client = type(
        "MutatingClient",
        (),
        {"chat": type("Chat", (), {"completions": completions})()},
    )()
    transport = OpenAICompatibleStructuredTransport(
        base_url=_BASE_URL,
        api_key_env=_ENV_NAME,
        system_template=_TEMPLATE,
        client=client,
        sleeper=lambda _seconds: None,
    )

    assert transport.complete(b'{"prompt_text":"locked"}', _policy()) == b'{"facts":[]}'
    assert completions.snapshots[0] == completions.snapshots[1]


def test_transport_accepts_exactly_one_stopped_text_choice() -> None:
    transport = _transport(_Client([_response('{"ok":true}')]))
    assert transport.complete(b"{}", _policy()) == b'{"ok":true}'


def test_transport_accepts_pure_text_sdk_object_shape() -> None:
    message = SimpleNamespace(
        role="assistant",
        content='{"ok":true}',
        annotations=[],
        audio=None,
        tool_calls=None,
        function_call=None,
        refusal=None,
    )
    choice = SimpleNamespace(finish_reason="stop", message=message)
    transport = _transport(_Client([SimpleNamespace(choices=[choice])]))

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


@pytest.mark.parametrize(
    "message",
    [
        {"role": "assistant", "content": "{}", "annotations": [{"kind": "citation"}]},
        {"role": "assistant", "content": "{}", "audio": {"id": "audio-1"}},
        {"role": "assistant", "content": "{}", "reasoning_content": "hidden"},
        SimpleNamespace(
            role="assistant",
            content="{}",
            annotations=[SimpleNamespace(kind="citation")],
            audio=None,
            tool_calls=None,
            function_call=None,
            refusal=None,
        ),
        SimpleNamespace(
            role="assistant",
            content="{}",
            annotations=[],
            audio=SimpleNamespace(id="audio-1"),
            tool_calls=None,
            function_call=None,
            refusal=None,
        ),
    ],
)
def test_transport_rejects_auxiliary_message_content_for_dict_and_sdk_objects(
    message: object,
) -> None:
    response = {
        "choices": [
            {
                "finish_reason": "stop",
                "message": message,
            }
        ]
    }
    client = _Client([response])

    with pytest.raises(SecAwareError) as exc_info:
        _transport(client).complete(b"{}", _policy())

    assert exc_info.value.code is ErrorCode.API_INVALID_RESPONSE


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


@pytest.mark.parametrize("boundary", ["provider", "scheduler", "response"])
def test_external_failure_exception_chains_are_secret_free(boundary: str) -> None:
    secret = f"raw-{boundary}-secret-value"

    if boundary == "provider":
        client = _Client([RuntimeError(secret)])
        transport = _transport(client)
    elif boundary == "scheduler":
        client = _Client([_StatusFailure(429)])

        def sleeper(_seconds: float) -> None:
            raise RuntimeError(secret)

        transport = OpenAICompatibleStructuredTransport(
            base_url=_BASE_URL,
            api_key_env=_ENV_NAME,
            system_template=_TEMPLATE,
            client=client,
            sleeper=sleeper,
        )
    else:

        class HostileResponse:
            @property
            def choices(self) -> object:
                raise RuntimeError(secret)

        client = _Client([HostileResponse()])
        transport = _transport(client)

    with pytest.raises(SecAwareError) as exc_info:
        transport.complete(b"{}", _policy())

    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert secret not in _exception_chain_text(exc_info.value)


def test_sdk_constructor_failure_exception_chain_is_secret_free(monkeypatch) -> None:
    secret = "raw-sdk-constructor-secret-value"

    def failing_factory(**_kwargs: object) -> object:
        raise RuntimeError(secret)

    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=failing_factory))
    with pytest.raises(SecAwareError) as exc_info:
        OpenAICompatibleStructuredTransport(
            base_url=_BASE_URL,
            api_key_env=_ENV_NAME,
            system_template=_TEMPLATE,
            environ={_ENV_NAME: "credential"},
        )

    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert secret not in _exception_chain_text(exc_info.value)

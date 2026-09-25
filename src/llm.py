"""Single chat transport for extraction, generation and blinded functional review.

No retries or semantic judgment: callers save the response and decide how a failed
attempt enters their source record or assigned-arm outcome.
"""
from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping, Sequence
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from prompt_mechanism_study.artifact_io import json_object
from prompt_mechanism_study.records import canonical_json


class ProviderError(RuntimeError):
    """A single provider attempt failed; preserve its bounded response if available."""

    def __init__(self, message: str, *, provider_response: bytes | None = None):
        super().__init__(message)
        self.provider_response = provider_response


def complete_chat(
    request_payload: dict[str, Any],
    evaluator: Mapping[str, Any],
    prompt: str,
    *,
    trace: Callable[[str, bytes], None] | None = None,
    continuation: Sequence[Mapping[str, str]] = (),
    source_first_delivery: bool = False,
) -> bytes:
    """Complete the declared chat request through the shared provider client.

    A local_vllm configuration uses the same messages, decoding and response validation,
    without Bailian's thinking parameter or an invented cloud credential.
    Optional tracing retains the credential-free wire body and response envelope
    for development replay and usage accounting; it does not alter either body.
    A continuation appends explicit chat turns after the unchanged source request.
    Source-first development delivery changes JSON presentation order only;
    artifact identities still use canonical JSON. Default delivery is unchanged.
    """
    local = evaluator.get("provider") == "local_vllm"
    key_name = evaluator.get("api_key_env")
    api_key = os.environ.get(key_name, "") if key_name else ""
    if not local and not api_key.strip():
        raise ProviderError("provider credential is unavailable")
    endpoint = evaluator["base_url"].rstrip("/") + "/chat/completions"
    response_format = evaluator.get("response_format", {"type": "json_object"})
    plain_local = local and response_format is None
    if not plain_local and (not isinstance(response_format, dict) or response_format.get("type") not in {
        "json_object",
        "json_schema",
    }):
        raise ProviderError("provider response format is invalid")
    if source_first_delivery:
        remaining = dict(request_payload)
        ordered = {key: remaining.pop(key) for key in (
            "request_kind", "annotation_phase", "source_prompt", "source_units"
        ) if key in remaining}
        ordered.update(remaining)
        source_message = json.dumps(ordered, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    else:
        source_message = canonical_json(request_payload)
    body = {
        "model": evaluator["model_id"],
        "messages": [
            {"role": "system", "content": prompt},
            {"role": "user", "content": source_message},
        ],
        "temperature": evaluator["temperature"],
        "top_p": evaluator["top_p"],
        "seed": evaluator["seed"],
        "n": 1,
        "response_format": response_format,
    }
    body["messages"].extend(dict(message) for message in continuation)
    if plain_local:
        # Explicit local-code delivery contract; legacy JSON requests unchanged.
        body.pop("response_format")
    if local and "chat_template_kwargs" in evaluator:
        template_kwargs = evaluator["chat_template_kwargs"]
        if not isinstance(template_kwargs, dict):
            raise ProviderError("local chat template kwargs must be an object")
        # vLLM forwards this explicit setting to the deployed model template.
        # Do not infer it from the differently scoped cloud thinking parameter.
        body["chat_template_kwargs"] = dict(template_kwargs)
    if evaluator.get("provider") == "deepseek":
        # DeepSeek exposes thinking under its native key and no seeded decoding
        # contract. Keep the provider difference explicit in the retained wire.
        body.pop("seed")
        body.pop("n")
        body["stream"] = False
        body["thinking"] = {"type": "enabled" if evaluator["enable_thinking"] else "disabled"}
    elif not local:
        body["enable_thinking"] = evaluator["enable_thinking"]
        if "thinking_budget" in evaluator:
            body["thinking_budget"] = evaluator["thinking_budget"]
    maximum_output_tokens = evaluator.get("maximum_output_tokens")
    if "maximum_completion_tokens" in evaluator:
        # DeepSeek names its completion limit max_tokens; Bailian uses
        # max_completion_tokens to include reasoning in the same budget.
        limit_field = "max_tokens" if evaluator.get("provider") == "deepseek" else "max_completion_tokens"
        body[limit_field] = evaluator["maximum_completion_tokens"]
    elif maximum_output_tokens is not None:
        body["max_tokens"] = maximum_output_tokens
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    # Canonical sorting is for artifact identity. At delivery it would reorder
    # response-schema properties, putting edges/nodes before the operation
    # inventory and reversing start/end evidence coordinates. Preserve the
    # declared schema sequence; source-message presentation is selected above.
    encoded_request = json.dumps(body, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    maximum_input_bytes = evaluator.get("maximum_input_bytes")
    if maximum_input_bytes is not None and (
        type(maximum_input_bytes) is not int or maximum_input_bytes <= 0
        or len(encoded_request) + 1024 > maximum_input_bytes
    ):
        raise ProviderError("provider request exceeds frozen input byte ceiling; not submitted")
    http_request = Request(
        endpoint,
        data=encoded_request,
        headers=headers,
        method="POST",
    )
    if trace is not None:
        trace("request", encoded_request)
    try:
        with urlopen(http_request, timeout=evaluator["timeout_seconds"]) as response:
            raw_outer = response.read(evaluator["max_response_bytes"] + 1)
        if trace is not None:
            trace("response", raw_outer)
        if len(raw_outer) > evaluator["max_response_bytes"]:
            raise ValueError
        outer = json_object(raw_outer)
        choices = outer["choices"]
        if not isinstance(choices, list) or len(choices) != 1:
            raise ValueError
        choice = choices[0]
        message = choice["message"]
        if not isinstance(message, dict):
            raise ValueError
        content = message.get("content")
        if choice.get("finish_reason") != "stop":
            raise ProviderError(
                f"provider completion did not finish with stop (finish_reason={choice.get('finish_reason')!r})",
                provider_response=raw_outer,
            )
        if (
            not isinstance(content, str)
            or not content.strip()
        ):
            raise ValueError
        encoded = content.encode("utf-8")
        if len(encoded) > evaluator["max_response_bytes"]:
            raise ValueError
        return encoded
    except HTTPError as error:
        try:
            with error:
                raw_error = error.read(evaluator["max_response_bytes"] + 1)
        except (OSError, ValueError):
            raw_error = b""
        if api_key:
            raw_error = raw_error.replace(api_key.encode("utf-8"), b"[REDACTED]")
        if trace is not None:
            trace("response", raw_error)
        raise ProviderError(f"provider HTTP error {error.code}", provider_response=raw_error) from None
    except (URLError, TimeoutError) as error:
        raise ProviderError(f"provider transport failed: {type(error).__name__}") from None
    except (ValueError, KeyError, TypeError, AttributeError):
        raise ProviderError("provider response envelope is invalid") from None

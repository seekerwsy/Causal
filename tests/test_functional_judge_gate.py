from __future__ import annotations
import json
from pathlib import Path
import pytest
from prompt_mechanism_study.measurement.functional_judge import (
    load_gate_inputs,
)


from prompt_mechanism_study.llm import complete_chat, ProviderError

ROOT = Path(__file__).parents[1]


def test_http_failure_retains_bounded_redacted_body_without_retry(monkeypatch):
    import io
    from urllib.error import HTTPError
    inputs = load_gate_inputs(ROOT)
    status = 400
    secret = 'test-only-error-credential'
    payload = json.dumps({'error': {'message': 'Rejected schema; echoed credential ' + secret}}).encode()
    observed, traces = [], []
    def reject(request, *, timeout):
        observed.append(request)
        raise HTTPError(request.full_url, status, 'rejected', {}, io.BytesIO(payload))
    monkeypatch.setenv('ALI_BAILIAN_API_KEY', secret)
    monkeypatch.setattr('prompt_mechanism_study.llm.urlopen', reject)
    with pytest.raises(ProviderError, match=f'provider HTTP error {status}') as caught:
        complete_chat({}, inputs.evaluator, inputs.prompt,
                         trace=lambda kind, raw: traces.append((kind, raw)))
    assert len(observed) == 1
    assert [kind for kind, _ in traces] == ['request', 'response']
    expected = payload.replace(secret.encode(), b'[REDACTED]')
    assert caught.value.provider_response == traces[-1][1] == expected
    assert all(secret.encode() not in raw for _, raw in traces)


def test_chat_request_preserves_frozen_decoding_and_repair_messages(monkeypatch) -> None:
    inputs = load_gate_inputs(ROOT)
    observed: dict[str, object] = {}

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _maximum: int) -> bytes:
            payload = {
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": '{"verdict":"unknown"}'},
                    }
                ]
            }
            return json.dumps(payload).encode()

    def _urlopen(request, *, timeout):
        observed["body"] = json.loads(request.data)
        observed["timeout"] = timeout
        observed['authorization'] = request.get_header('Authorization')
        return _Response()

    monkeypatch.setenv("ALI_BAILIAN_API_KEY", "test-only")
    monkeypatch.setattr("prompt_mechanism_study.llm.urlopen", _urlopen)

    evaluator = dict(inputs.evaluator)
    evaluator.update(enable_thinking=True, maximum_completion_tokens=8192, thinking_budget=4096)
    # Protect the current record format at the transport boundary; no separate
    # provider mock or obsolete indexed-inventory test is needed.
    from prompt_mechanism_study.tsg.prompt_contract import open_concept_catalog
    from prompt_mechanism_study.tsg.source_codec import contract_decision_request
    from prompt_mechanism_study.tsg.source_records import record_request, record_response_format
    source = record_request(contract_decision_request(
        dict(task_id='wire-format', prompt='Return the supplied value.', language='python'),
        open_concept_catalog()))
    evaluator['response_format'] = record_response_format(source)
    traces = []
    continuation = [dict(role='assistant', content='{"verdict":"unknown"}'),
                    dict(role='user', content='Revise the draft using the original source.')]
    returned = complete_chat({}, evaluator, inputs.prompt,
                               trace=lambda kind, raw: traces.append((kind, raw)), continuation=continuation)
    assert [kind for kind, _ in traces] == ['request', 'response']
    assert json.loads(traces[0][1]) == observed['body']
    assert json.loads(traces[1][1])['choices'][0]['message']['content'].encode() == returned
    assert all(b'test-only' not in raw for _, raw in traces)

    body = observed["body"]
    assert isinstance(body, dict)
    assert body["model"] == evaluator['model_id']
    assert body['response_format'] == evaluator['response_format']
    requirements = body['response_format']['json_schema']['schema']['properties']['requirements']
    assert list(requirements['items']['properties'])[-1] == 'fact'
    assert body['messages'][:2] == [dict(role='system', content=inputs.prompt), dict(role='user', content='{}')]
    assert body['messages'][2:] == continuation
    assert body['max_completion_tokens'] == 8192 and 'max_tokens' not in body
    assert body['thinking_budget'] == 4096 and body['enable_thinking'] is True
    assert body['temperature'] == evaluator['temperature']
    assert body['seed'] == evaluator['seed']
    assert observed['authorization'] == 'Bearer test-only'
    assert body["n"] == 1

    complete_chat({}, {**evaluator, 'provider': 'deepseek', 'model_id': 'deepseek-flash',
                          'base_url': 'https://api.deepseek.com'}, inputs.prompt,
                     continuation=continuation)
    deepseek_body = observed['body']
    assert deepseek_body['max_tokens'] == 8192
    assert not {'max_completion_tokens', 'seed', 'n', 'thinking_budget', 'enable_thinking'} & deepseek_body.keys()
    assert deepseek_body['thinking'] == {'type': 'enabled'} and deepseek_body['stream'] is False
    assert deepseek_body['messages'] == body['messages']

    local = {**evaluator, 'provider': 'local_vllm', 'api_key_env': None,
             'base_url': 'http://127.0.0.1:8000/v1', 'response_format': None}
    complete_chat({}, local, inputs.prompt)
    assert not {'enable_thinking', 'thinking', 'chat_template_kwargs', 'response_format'} & observed['body'].keys()
    complete_chat({}, {**local, 'chat_template_kwargs': {'enable_thinking': False}}, inputs.prompt)
    assert observed['body']['chat_template_kwargs'] == {'enable_thinking': False}
    assert 'enable_thinking' not in observed['body'] and observed['authorization'] is None

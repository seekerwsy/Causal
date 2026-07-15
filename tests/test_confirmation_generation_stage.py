from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
import functools
import hashlib
import inspect
import os
import threading

import pytest

from secaware.errors import ErrorCode, SecAwareError
from secaware.config import GenerationConfig, OpenAICompatibleConfig, load_config
from secaware.generation.confirmation import (
    CONFIRMATION_PROVIDER_RESULT_POLICY_SHA256,
    execute_confirmation_requests,
)
from secaware.io.jsonl import read_jsonl
from secaware.io.transaction import ArtifactTransaction, TransactionStateError
from secaware.pipeline.stages.prompt_variants import (
    PROMPT_VARIANT_OUTPUTS,
    run_prompt_variant_freeze_stage,
)
from secaware.pipeline.stages.randomization import (
    RANDOMIZATION_OUTPUTS,
    run_confirmation_randomization_stage,
)
import secaware.pipeline.stage_contracts as stage_contracts
import secaware.generation.openai_compatible_provider as openai_provider
import secaware.generation.confirmation as confirmation_generation
import secaware.schema.generation as generation_schema
from secaware.pipeline.stages.confirmation_generation import (
    CONFIRMATION_GENERATION_OUTPUTS,
    run_confirmation_generation_stage,
)
from secaware.pipeline.bounded_traversal import BoundedTreeEntry
import secaware.pipeline.stages.confirmation_generation as confirmation_stage
from secaware.pipeline.manifest import build_stage_fingerprint
from secaware import __version__
from secaware.schema.experiments import AssignmentExecutionRecord, AssignmentExecutionStatus
from secaware.schema.experiments import (
    ArmRole,
    AssignmentRecord,
    PromptVariantRecord,
    RandomizationManifestRecord,
)
from secaware.schema.generation import (
    GenerationAttemptRecord,
    GenerationParameters,
    GenerationRequestRecord,
    ProviderResultEnvelope,
    ProviderUsageRecord,
    build_generation_request_id,
    revalidate_generation_request_envelope,
)
from secaware.schema.generation import GenerationProvenance
from secaware.schema.common import MAX_MODEL_ID_CHARS
from secaware.schema.records import CanonicalGeneratedCodeRecord
from test_prompt_variant_freeze_stage import _stage_store
from test_confirmation_generation_planner import _assignment_and_variant, _generation_config
from secaware.generation.request_planner import plan_confirmation_requests


@dataclass(frozen=True)
class _Result:
    code: str | None
    finish_reason: str
    provenance: GenerationProvenance = field(
        default_factory=lambda: GenerationProvenance(
            producer="locked-test-provider", producer_version="v1"
        )
    )


class _Provider:
    def __init__(self, *, reverse: bool = False, content_filter_assignment: str | None = None):
        self.reverse = reverse
        self.content_filter_assignment = content_filter_assignment

    def generate_many(self, requests):
        items = list(requests)
        if self.reverse:
            items.reverse()
        return tuple(
            (
                item.request_id,
                _envelope(item, None, "content_filter")
                if item.assignment_id == self.content_filter_assignment
                else _envelope(item, f"# code for {item.assignment_id}\n", "stop"),
            )
            for item in items
        )


@pytest.fixture(autouse=True)
def _locked_test_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        confirmation_stage,
        "_provider_from_frozen_config",
        lambda _config, **_kwargs: _Provider(),
    )


@pytest.fixture(scope="module")
def randomized_store(tmp_path_factory: pytest.TempPathFactory):
    config, store = _stage_store(tmp_path_factory.mktemp("confirmation-generation"), task_count=20)
    run_prompt_variant_freeze_stage(config, store, force=False)
    run_confirmation_randomization_stage(config, store, force=False)
    return config, store


def test_confirmation_generation_future_guard_allows_observed_oracle(
    tmp_path: Path,
) -> None:
    _config, store = _stage_store(tmp_path, task_count=2)
    observed = store.path("oracle", "observed_oracle.jsonl")
    observed.write_text("{}\n", encoding="utf-8")

    confirmation_stage._guard_no_oracle_or_analysis(store)

    store.path("oracle", "confirmation_oracle.jsonl").write_text("{}\n", encoding="utf-8")
    with pytest.raises(SecAwareError):
        confirmation_stage._guard_no_oracle_or_analysis(store)


@pytest.mark.parametrize(
    "relative_paths",
    (
        ("Observed_Oracle.jsonl",),
        ("nested/observed_oracle.jsonl",),
        ("other.jsonl",),
        ("observed_oracle.jsonl", "other.jsonl"),
    ),
)
def test_confirmation_generation_oracle_guard_requires_one_exact_canonical_path(
    tmp_path: Path,
    relative_paths: tuple[str, ...],
) -> None:
    _config, store = _stage_store(tmp_path, task_count=2)

    def traversal(root: Path, **_limits: int):
        if root.name != "oracle":
            return iter(())
        return iter(
            BoundedTreeEntry(
                relative_path=relative,
                name=Path(relative).name,
                is_file=True,
                is_dir=False,
            )
            for relative in relative_paths
        )

    with pytest.raises(SecAwareError):
        confirmation_stage._guard_no_oracle_or_analysis(store, traversal=traversal)


def test_confirmation_generation_oracle_guard_accepts_only_exact_canonical_path(
    tmp_path: Path,
) -> None:
    _config, store = _stage_store(tmp_path, task_count=2)

    def traversal(root: Path, **_limits: int):
        if root.name == "oracle":
            return iter(
                (
                    BoundedTreeEntry(
                        relative_path="observed_oracle.jsonl",
                        name="observed_oracle.jsonl",
                        is_file=True,
                        is_dir=False,
                    ),
                )
            )
        return iter(())

    confirmation_stage._guard_no_oracle_or_analysis(store, traversal=traversal)


def _requests():
    pairs = (_assignment_and_variant(task_id="task-a"), _assignment_and_variant(task_id="task-b"))
    return plan_confirmation_requests(
        tuple(item[0] for item in pairs), tuple(item[1] for item in pairs), _generation_config()
    )


def _envelope(request, code: str | None, finish_reason: str = "stop"):
    return ProviderResultEnvelope.from_content(
        request_id=request.request_id,
        model_id=request.model_id,
        finish_reason=finish_reason,
        code=code,
        usage=ProviderUsageRecord(prompt_tokens=4, completion_tokens=3, total_tokens=7),
        attempts=(
            GenerationAttemptRecord(
                schema_version="1.0",
                request_id=request.request_id,
                attempt=1,
                outcome="success",
                error_code=None,
                retryable=False,
                backoff_seconds=0.0,
            ),
        ),
        provenance=GenerationProvenance(producer="strict-test", producer_version="v1"),
        provider_policy_sha256=CONFIRMATION_PROVIDER_RESULT_POLICY_SHA256,
        runtime_fingerprint_sha256="b" * 64,
    )


def _reseal_request(
    request: GenerationRequestRecord,
    *,
    prompt: str | None = None,
    parameters: GenerationParameters | None = None,
) -> GenerationRequestRecord:
    payload = request.model_dump(mode="python", exclude={"request_id"})
    if prompt is not None:
        payload["prompt"] = prompt
        payload["prompt_sha256"] = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    if parameters is not None:
        payload["parameters"] = parameters
    elif type(payload["parameters"]) is not GenerationParameters:
        payload["parameters"] = GenerationParameters.model_validate(payload["parameters"])
    identity = {key: value for key, value in payload.items() if key != "prompt"}
    identity["parameters"] = payload["parameters"]
    payload["request_id"] = build_generation_request_id(**identity)
    return GenerationRequestRecord.model_validate(payload)


def _resource_config(**updates: object) -> GenerationConfig:
    payload = _generation_config().model_dump(mode="python")
    payload.update(updates)
    return GenerationConfig.model_validate(payload)


@pytest.mark.parametrize(
    "updates",
    (
        {
            "confirmation_max_attempts_per_request": 1,
            "openai_compatible": OpenAICompatibleConfig(
                base_url="https://example.test/v1", max_attempts=2
            ),
        },
        {
            "confirmation_max_timeout_seconds_per_attempt": 1.0,
            "openai_compatible": OpenAICompatibleConfig(
                base_url="https://example.test/v1", timeout_seconds=2.0
            ),
        },
        {
            "confirmation_max_worst_case_wait_seconds": 1.0,
            "openai_compatible": OpenAICompatibleConfig(
                base_url="https://example.test/v1", timeout_seconds=2.0
            ),
        },
    ),
)
def test_generation_config_closes_attempt_timeout_and_wait_budgets(
    updates: dict[str, object],
) -> None:
    payload = _generation_config().model_dump(mode="python")
    payload.update(updates)
    with pytest.raises(Exception):
        GenerationConfig.model_validate(payload)


def test_confirmation_executor_closes_infinite_single_request_iterator_after_two_reads() -> None:
    request = _requests()[0]

    class Infinite:
        def __init__(self):
            self.reads = 0
            self.closed = False

        def __iter__(self):
            return self

        def __next__(self):
            self.reads += 1
            return (request.request_id, _envelope(request, "code\n"))

        def close(self):
            self.closed = True

    stream = Infinite()

    class Provider:
        def generate_many(self, _requests):
            return stream

    with pytest.raises(SecAwareError):
        execute_confirmation_requests((request,), Provider())
    assert stream.reads == 2
    assert stream.closed is True


def test_confirmation_executor_rejects_duck_result_envelope() -> None:
    request = _requests()[0]

    class Provider:
        def generate_many(self, _requests):
            return ((request.request_id, _Result("code\n", "stop")),)

    with pytest.raises(SecAwareError):
        execute_confirmation_requests((request,), Provider())


def test_provider_result_envelope_bounds_escaped_provenance_metadata() -> None:
    request = _requests()[0]
    with pytest.raises(Exception):
        ProviderResultEnvelope.from_content(
            request_id=request.request_id,
            model_id=request.model_id,
            finish_reason="stop",
            code="code\n",
            usage=ProviderUsageRecord(prompt_tokens=1, completion_tokens=1, total_tokens=2),
            attempts=(
                GenerationAttemptRecord(
                    schema_version="1.0",
                    request_id=request.request_id,
                    attempt=1,
                    outcome="success",
                    error_code=None,
                    retryable=False,
                    backoff_seconds=0.0,
                ),
            ),
            provenance=GenerationProvenance(
                producer="\x01" * 4_096,
                producer_version="v1",
            ),
            provider_policy_sha256=CONFIRMATION_PROVIDER_RESULT_POLICY_SHA256,
            runtime_fingerprint_sha256="b" * 64,
        )


@pytest.mark.parametrize("field", ("attempts", "provenance", "usage"))
def test_confirmation_executor_rejects_result_missing_required_terminal_metadata(
    field: str,
) -> None:
    request = _requests()[0]
    envelope = _envelope(request, "code\n")
    replacement = () if field == "attempts" else None
    malformed = envelope.model_copy(update={field: replacement})

    class Provider:
        def generate_many(self, _requests):
            return ((request.request_id, malformed),)

    with pytest.raises(SecAwareError):
        execute_confirmation_requests((request,), Provider())


def test_provider_provenance_and_attempts_are_bound_into_execution_identity() -> None:
    request = _requests()[0]

    def envelope(*, producer: str, retries: bool) -> ProviderResultEnvelope:
        attempts = []
        if retries:
            attempts.append(
                GenerationAttemptRecord(
                    schema_version="1.0",
                    request_id=request.request_id,
                    attempt=1,
                    outcome="retry",
                    error_code=int(ErrorCode.API_TIMEOUT),
                    retryable=True,
                    backoff_seconds=0.0,
                )
            )
        attempts.append(
            GenerationAttemptRecord(
                schema_version="1.0",
                request_id=request.request_id,
                attempt=len(attempts) + 1,
                outcome="success",
                error_code=None,
                retryable=False,
                backoff_seconds=0.0,
            )
        )
        return ProviderResultEnvelope.from_content(
            request_id=request.request_id,
            model_id=request.model_id,
            finish_reason="stop",
            code="same code\n",
            usage=ProviderUsageRecord(prompt_tokens=1, completion_tokens=1, total_tokens=2),
            attempts=tuple(attempts),
            provenance=GenerationProvenance(producer=producer, producer_version="v1"),
            provider_policy_sha256=CONFIRMATION_PROVIDER_RESULT_POLICY_SHA256,
            runtime_fingerprint_sha256="b" * 64,
        )

    class Provider:
        def __init__(self, value: ProviderResultEnvelope) -> None:
            self.value = value

        def generate_many(self, _requests):
            return ((request.request_id, self.value),)

    baseline = execute_confirmation_requests(
        (request,), Provider(envelope(producer="provider-a", retries=False))
    )[0][0]
    provenance_drift = execute_confirmation_requests(
        (request,), Provider(envelope(producer="provider-b", retries=False))
    )[0][0]
    attempt_drift = execute_confirmation_requests(
        (request,), Provider(envelope(producer="provider-a", retries=True))
    )[0][0]
    assert baseline.execution_id != provenance_drift.execution_id
    assert baseline.execution_id != attempt_drift.execution_id


def test_oversize_first_result_prevents_later_provider_call() -> None:
    requests = _requests()
    calls: list[tuple[str, ...]] = []

    class Provider:
        def generate_many(self, batch):
            calls.append(tuple(item.request_id for item in batch))
            request = batch[0]
            return ((request.request_id, _envelope(request, "x" * 1_048_577)),)

    with pytest.raises(SecAwareError):
        execute_confirmation_requests(requests, Provider())
    assert calls == [(requests[0].request_id,)]


@pytest.mark.parametrize(
    "case",
    (
        "request_count",
        "missing_token_cap",
        "max_tokens",
        "stop_count",
        "stop_item",
        "stop_total",
        "parameters",
        "prompt_per_request",
        "prompt_total",
        "projected_output",
        "json_escape_projection",
    ),
)
def test_resource_preflight_rejects_before_any_provider_call(case: str) -> None:
    requests = list(_requests())
    config = _resource_config()
    if case == "request_count":
        config = _resource_config(confirmation_max_requests=1)
    elif case == "missing_token_cap":
        requests = [
            _reseal_request(
                requests[0], parameters=GenerationParameters(values={"temperature": 0.0})
            )
        ]
    elif case == "max_tokens":
        requests = [
            _reseal_request(requests[0], parameters=GenerationParameters(values={"max_tokens": 2}))
        ]
        config = _resource_config(confirmation_max_tokens_per_request=1)
    elif case == "stop_count":
        requests = [
            _reseal_request(
                requests[0], parameters=GenerationParameters(values={"stop": ["a", "b"]})
            )
        ]
        config = _resource_config(confirmation_max_stop_items=1)
    elif case == "stop_item":
        requests = [
            _reseal_request(requests[0], parameters=GenerationParameters(values={"stop": "ab"}))
        ]
        config = _resource_config(confirmation_max_stop_item_chars=1)
    elif case == "stop_total":
        requests = [
            _reseal_request(
                requests[0], parameters=GenerationParameters(values={"stop": ["aa", "b"]})
            )
        ]
        config = _resource_config(
            confirmation_max_stop_item_chars=2,
            confirmation_max_stop_total_chars=2,
        )
    elif case == "parameters":
        requests = [
            _reseal_request(
                requests[0], parameters=GenerationParameters(values={"temperature": 0.0})
            )
        ]
        config = _resource_config(confirmation_max_parameters_bytes=1)
    elif case == "prompt_per_request":
        config = _resource_config(confirmation_max_prompt_bytes_per_request=1)
        requests = [requests[0]]
    elif case == "prompt_total":
        requests = [
            _reseal_request(request, prompt=character * 600)
            for request, character in zip(requests, ("a", "b"), strict=True)
        ]
        config = _resource_config(
            confirmation_max_prompt_bytes_per_request=1_024,
            confirmation_max_total_prompt_bytes=1_024,
        )
    elif case == "projected_output":
        requests = [requests[0]]
        config = _resource_config(confirmation_max_projected_jsonl_bytes=1_024)
    else:
        requests = [requests[0]]
        config = _resource_config(
            confirmation_max_code_bytes_per_result=3 * 1024 * 1024,
            confirmation_max_total_code_bytes=3 * 1024 * 1024,
            confirmation_max_projected_jsonl_bytes=16 * 1024 * 1024,
        )

    calls = 0

    class Provider:
        def generate_many(self, batch):
            nonlocal calls
            calls += 1
            request = batch[0]
            return ((request.request_id, _envelope(request, "code\n")),)

    with pytest.raises(SecAwareError):
        execute_confirmation_requests(tuple(requests), Provider(), config)
    assert calls == 0


def test_provider_attempt_budget_is_enforced_before_later_request() -> None:
    requests = _requests()
    calls = 0

    class Provider:
        def generate_many(self, batch):
            nonlocal calls
            calls += 1
            request = batch[0]
            attempts = (
                GenerationAttemptRecord(
                    schema_version="1.0",
                    request_id=request.request_id,
                    attempt=1,
                    outcome="retry",
                    error_code=int(ErrorCode.API_TIMEOUT),
                    retryable=True,
                    backoff_seconds=0.0,
                ),
                GenerationAttemptRecord(
                    schema_version="1.0",
                    request_id=request.request_id,
                    attempt=2,
                    outcome="success",
                    error_code=None,
                    retryable=False,
                    backoff_seconds=0.0,
                ),
            )
            return (
                (
                    request.request_id,
                    ProviderResultEnvelope.from_content(
                        request_id=request.request_id,
                        model_id=request.model_id,
                        finish_reason="stop",
                        code="code\n",
                        usage=ProviderUsageRecord(
                            prompt_tokens=1, completion_tokens=1, total_tokens=2
                        ),
                        attempts=attempts,
                        provenance=GenerationProvenance(
                            producer="strict-test", producer_version="v1"
                        ),
                        provider_policy_sha256=CONFIRMATION_PROVIDER_RESULT_POLICY_SHA256,
                        runtime_fingerprint_sha256="b" * 64,
                    ),
                ),
            )

    config = _resource_config(
        confirmation_max_attempts_per_request=1,
        confirmation_max_total_provider_attempts=2,
    )
    with pytest.raises(SecAwareError):
        execute_confirmation_requests(requests, Provider(), config)
    assert calls == 1


def test_default_wait_budget_accepts_240_assignments_and_smaller_budget_is_zero_call() -> None:
    pairs = tuple(_assignment_and_variant(task_id=f"wait-task-{index}") for index in range(240))
    provider_config = OpenAICompatibleConfig(base_url="https://example.test/v1")
    config = GenerationConfig(
        provider="openai_compatible",
        models=["model-a"],
        seeds=[1],
        confirmation_seeds=[101],
        openai_compatible=provider_config,
    )
    requests = tuple(
        plan_confirmation_requests(
            tuple(pair[0] for pair in pairs),
            tuple(pair[1] for pair in pairs),
            config,
        )
    )
    calls = 0

    class Provider:
        def generate_many(self, batch):
            nonlocal calls
            calls += 1
            request = batch[0]
            return ((request.request_id, _envelope(request, "code\n")),)

    executions, codes = execute_confirmation_requests(requests, Provider(), config)
    assert len(executions) == len(codes) == 240
    assert calls == 240

    constrained_payload = config.model_dump(mode="python")
    constrained_payload["confirmation_max_worst_case_wait_seconds"] = 43_900.0
    constrained = GenerationConfig.model_validate(constrained_payload)
    calls = 0
    with pytest.raises(SecAwareError):
        execute_confirmation_requests(requests, Provider(), constrained)
    assert calls == 0


def test_128_mib_control_character_projection_is_rejected_before_provider_call() -> None:
    pairs = tuple(_assignment_and_variant(task_id=f"escape-task-{index}") for index in range(43))
    config = _resource_config(
        confirmation_max_code_bytes_per_result=3 * 1024 * 1024,
        confirmation_max_total_code_bytes=128 * 1024 * 1024,
    )
    requests = tuple(
        plan_confirmation_requests(
            tuple(pair[0] for pair in pairs),
            tuple(pair[1] for pair in pairs),
            config,
        )
    )
    calls = 0

    class Provider:
        def generate_many(self, _batch):
            nonlocal calls
            calls += 1
            raise AssertionError("provider called after failed output projection")

    with pytest.raises(SecAwareError):
        execute_confirmation_requests(requests, Provider(), config)
    assert calls == 0


def _request_with_exact_serialized_line_chars(
    request: GenerationRequestRecord,
    target_chars: int,
) -> GenerationRequestRecord:
    baseline = _reseal_request(request, prompt="a")
    _bytes, baseline_chars = confirmation_generation._serialized_request_shape(baseline)
    fixed_chars = baseline_chars - 1
    delta = target_chars - fixed_chars
    if delta < 1:
        raise ValueError("target line is too small")
    controls, plain = divmod(delta, 6)
    prompt = "\x01" * controls + "a" * plain
    result = _reseal_request(request, prompt=prompt)
    assert confirmation_generation._serialized_request_shape(result)[1] == target_chars
    return result


def test_canonical_request_json_line_boundary_plus_minus_one_is_exact_and_zero_call() -> None:
    request = _requests()[0]
    accepted = _request_with_exact_serialized_line_chars(request, 4_000_000 - 2)
    rejected = _request_with_exact_serialized_line_chars(request, 4_000_000 - 1)
    assert confirmation_generation._serialized_request_shape(accepted)[1] + 1 == 3_999_999
    assert confirmation_generation._serialized_request_shape(rejected)[1] + 1 == 4_000_000
    calls = 0

    class Provider:
        def generate_many(self, _batch):
            nonlocal calls
            calls += 1
            raise AssertionError("provider called after request line bound")

    with pytest.raises(SecAwareError):
        execute_confirmation_requests((rejected,), Provider(), _resource_config())
    assert calls == 0


def test_worst_case_code_json_line_boundary_accepts_last_safe_cap_and_rejects_next() -> None:
    request = _requests()[0]
    base_chars = confirmation_generation._canonical_code_line_base_chars(
        request, _resource_config()
    )
    accepted_cap = (4_000_000 - base_chars - 2) // 6
    rejected_cap = accepted_cap + 1
    assert base_chars + 6 * accepted_cap + 1 < 4_000_000
    assert base_chars + 6 * rejected_cap + 1 >= 4_000_000
    calls = 0

    class Provider:
        def generate_many(self, batch):
            nonlocal calls
            calls += 1
            item = batch[0]
            return ((item.request_id, _envelope(item, "code\n")),)

    accepted_config = _resource_config(
        confirmation_max_code_bytes_per_result=accepted_cap,
        confirmation_max_total_code_bytes=accepted_cap,
    )
    execute_confirmation_requests((request,), Provider(), accepted_config)
    assert calls == 1
    rejected_config = _resource_config(
        confirmation_max_code_bytes_per_result=rejected_cap,
        confirmation_max_total_code_bytes=rejected_cap,
    )
    calls = 0
    with pytest.raises(SecAwareError):
        execute_confirmation_requests((request,), Provider(), rejected_config)
    assert calls == 0


def test_model_id_boundary_rejects_before_provider_and_accepts_maximum() -> None:
    source = _requests()[0]
    accepted_model = "m" * MAX_MODEL_ID_CHARS
    payload = source.model_dump(mode="python", exclude={"request_id"})
    payload["model_id"] = accepted_model
    payload["parameters"] = GenerationParameters.model_validate(payload["parameters"])
    payload["request_id"] = build_generation_request_id(
        **{key: value for key, value in payload.items() if key != "prompt"}
    )
    accepted = GenerationRequestRecord.model_validate(payload)
    calls = 0

    class Provider:
        def generate_many(self, batch):
            nonlocal calls
            calls += 1
            item = batch[0]
            return ((item.request_id, _envelope(item, "code\n")),)

    execute_confirmation_requests((accepted,), Provider(), _resource_config())
    assert calls == 1

    rejected_model = "m" * (MAX_MODEL_ID_CHARS + 1)
    forged = accepted.model_copy(update={"model_id": rejected_model})
    calls = 0
    with pytest.raises(SecAwareError):
        execute_confirmation_requests((forged,), Provider(), _resource_config())
    assert calls == 0


def test_700001_control_code_is_never_configurable_and_provider_violation_stops_batch() -> None:
    requests = _requests()
    impossible = _resource_config(
        confirmation_max_code_bytes_per_result=700_001,
        confirmation_max_total_code_bytes=700_001,
    )
    calls = 0

    class Provider:
        def generate_many(self, batch):
            nonlocal calls
            calls += 1
            item = batch[0]
            return ((item.request_id, _envelope(item, "\x01" * 700_001)),)

    with pytest.raises(SecAwareError):
        execute_confirmation_requests((requests[0],), Provider(), impossible)
    assert calls == 0

    calls = 0
    with pytest.raises(SecAwareError):
        execute_confirmation_requests(requests, Provider(), _resource_config())
    assert calls == 1


def _persisted_bundle(config, store):
    run_confirmation_generation_stage(config, store, force=False)
    requests = tuple(
        read_jsonl(
            store.path("generation", "confirmation_requests.jsonl"),
            GenerationRequestRecord,
            required=True,
            allow_empty=False,
        )
    )
    executions = tuple(
        read_jsonl(
            store.path("generation", "confirmation_execution.jsonl"),
            AssignmentExecutionRecord,
            required=True,
            allow_empty=False,
        )
    )
    codes = tuple(
        read_jsonl(
            store.path("generation", "confirmation_code.jsonl"),
            CanonicalGeneratedCodeRecord,
            required=True,
            allow_empty=False,
        )
    )
    assignments = tuple(
        read_jsonl(
            store.path("interventions", "assignments.jsonl"),
            AssignmentRecord,
            required=True,
            allow_empty=False,
        )
    )
    variants = tuple(
        read_jsonl(
            store.path("interventions", "prompt_variants.jsonl"),
            PromptVariantRecord,
            required=True,
            allow_empty=False,
        )
    )
    manifest = read_jsonl(
        store.path("interventions", "randomization_manifest.jsonl"),
        RandomizationManifestRecord,
        required=True,
        allow_empty=False,
    )[0]
    snapshot = confirmation_stage._InputSnapshot(
        files=(), assignments=assignments, variants=variants, randomization_manifest=manifest
    )
    return snapshot, (requests, executions, codes)


def _secaware_traceback_locals(error: BaseException) -> str:
    retained: list[str] = []
    cursor = error.__traceback__
    while cursor is not None:
        if "/src/secaware/" in cursor.tb_frame.f_code.co_filename.replace("\\", "/"):
            retained.append(repr(dict(cursor.tb_frame.f_locals)))
        cursor = cursor.tb_next
    return "\n".join(retained)


def test_valid_terminal_generation_failure_keeps_assignment_coverage() -> None:
    requests = _requests()
    records, codes = execute_confirmation_requests(
        requests,
        _Provider(content_filter_assignment=requests[0].assignment_id),
    )
    assert {item.assignment_id for item in records} == {item.assignment_id for item in requests}
    assert sum(item.status is AssignmentExecutionStatus.TERMINAL_NO_CODE for item in records) == 1
    assert len(codes) == len(records) - 1
    assert {item.assignment_id for item in codes} == {
        item.assignment_id for item in records if item.status is AssignmentExecutionStatus.GENERATED
    }
    terminal = next(
        item for item in records if item.status is AssignmentExecutionStatus.TERMINAL_NO_CODE
    )
    assert terminal.provider_result_sha256
    assert terminal.provider_provenance_sha256
    assert terminal.provider_runtime_sha256
    assert terminal.provider_policy_sha256 == CONFIRMATION_PROVIDER_RESULT_POLICY_SHA256
    assert terminal.usage_sha256
    assert terminal.attempt_count == 1


def test_provider_execution_order_does_not_change_canonical_outputs() -> None:
    requests = _requests()
    assert execute_confirmation_requests(requests, _Provider()) == execute_confirmation_requests(
        tuple(reversed(requests)), _Provider(reverse=True)
    )


@pytest.mark.parametrize("mutation", ("duplicate", "omit", "extra", "unknown_finish"))
def test_execution_rejects_non_exact_or_malformed_provider_coverage(mutation: str) -> None:
    requests = _requests()

    class Provider(_Provider):
        def generate_many(self, values):
            outputs = list(super().generate_many(values))
            if mutation == "duplicate":
                outputs.append(outputs[0])
            elif mutation == "omit":
                outputs.pop()
            elif mutation == "extra":
                outputs.append(("req_" + "f" * 64, _Result("code", "stop")))
            else:
                outputs[0] = (outputs[0][0], _Result(None, "length"))
            return tuple(outputs)

    with pytest.raises(Exception):
        execute_confirmation_requests(requests, Provider())


def test_provider_infrastructure_errors_abort_without_terminal_record() -> None:
    requests = _requests()

    class Provider:
        def generate_many(self, _values):
            raise RuntimeError("transport failed with secret prompt")

    with pytest.raises(Exception) as caught:
        execute_confirmation_requests(requests, Provider())
    assert "secret prompt" not in str(caught.value)


def test_provider_secaware_error_is_rewrapped_with_fixed_safe_details() -> None:
    secret = "provider-error-sensitive-payload"

    class Provider:
        def generate_many(self, _values):
            raise SecAwareError(
                code=ErrorCode.API_AUTH,
                stage=secret,
                message=secret,
                details={"nested": {"value": secret}},
                retryable=True,
            )

    with pytest.raises(SecAwareError) as exc_info:
        execute_confirmation_requests((_requests()[0],), Provider())
    error = exc_info.value
    assert error.code is ErrorCode.API_AUTH
    assert error.stage == "generate-confirmation"
    assert error.message == "confirmation provider request failed"
    assert error.details == {"retryable": True}
    assert secret not in str(error)
    assert secret not in _secaware_traceback_locals(error)


def test_active_fatal_error_has_priority_over_iterator_cleanup_fatal() -> None:
    active = MemoryError("active-fatal")
    cleanup = SystemExit("cleanup-fatal")

    class Stream:
        def __iter__(self):
            return self

        def __next__(self):
            raise active

        def close(self):
            raise cleanup

    class Provider:
        def generate_many(self, _values):
            return Stream()

    with pytest.raises(MemoryError) as exc_info:
        execute_confirmation_requests((_requests()[0],), Provider())
    assert exc_info.value is active


def test_iterator_cleanup_fatal_has_priority_over_active_nonfatal_error() -> None:
    cleanup = SystemExit("cleanup-fatal")

    class Stream:
        def __iter__(self):
            return self

        def __next__(self):
            raise RuntimeError("ordinary provider failure")

        def close(self):
            raise cleanup

    class Provider:
        def generate_many(self, _values):
            return Stream()

    with pytest.raises(SystemExit) as exc_info:
        execute_confirmation_requests((_requests()[0],), Provider())
    assert exc_info.value is cleanup


def test_confirmation_executor_failure_releases_raw_code_and_provider_from_frames() -> None:
    secret = "confirmation-raw-code-frame-secret"
    provider_secret = "confirmation-provider-frame-secret"

    class Provider:
        def __repr__(self) -> str:
            return provider_secret

        def generate_many(self, values):
            request = tuple(values)[0]
            return ((request.request_id, _Result(secret, "length")),)

    with pytest.raises(SecAwareError) as exc_info:
        execute_confirmation_requests((_requests()[0],), Provider())
    retained = _secaware_traceback_locals(exc_info.value)
    assert secret not in retained
    assert provider_secret not in retained


def test_single_request_adapter_ordinary_failure_releases_provider_request_and_result() -> None:
    provider_secret = "adapter-provider-secret"
    result_secret = "adapter-result-secret"
    request = _requests()[0]

    class Provider:
        def __repr__(self) -> str:
            return provider_secret

        def generate(self, _request, _system_template):
            return _Result(result_secret, "stop")

    adapter = confirmation_stage._SingleRequestProviderAdapter(Provider(), "")
    with pytest.raises(TypeError) as exc_info:
        adapter.generate_many((request,))
    retained = _secaware_traceback_locals(exc_info.value)
    assert provider_secret not in retained
    assert result_secret not in retained
    assert request.prompt not in retained


@pytest.mark.parametrize("signal_type", [MemoryError, KeyboardInterrupt, SystemExit])
def test_single_request_adapter_preserves_fatal_identity_and_releases_frames(
    signal_type: type[BaseException],
) -> None:
    provider_secret = f"adapter-{signal_type.__name__}-provider-secret"
    request = _requests()[0]
    signal = signal_type("adapter-control-flow")

    class Provider:
        def __repr__(self) -> str:
            return provider_secret

        def generate(self, _request, _system_template):
            raise signal

    adapter = confirmation_stage._SingleRequestProviderAdapter(Provider(), "")
    with pytest.raises(signal_type) as exc_info:
        adapter.generate_many((request,))
    assert exc_info.value is signal
    retained = _secaware_traceback_locals(signal)
    assert provider_secret not in retained
    assert request.prompt not in retained


def test_single_request_adapter_active_fatal_precedes_cleanup_fatal() -> None:
    active = MemoryError("adapter-active-fatal")
    cleanup = SystemExit("adapter-cleanup-fatal-secret")

    class Requests:
        def __iter__(self):
            return self

        def __next__(self):
            raise active

        def close(self):
            raise cleanup

    adapter = confirmation_stage._SingleRequestProviderAdapter(object(), "")
    with pytest.raises(MemoryError) as exc_info:
        adapter.generate_many(Requests())  # type: ignore[arg-type]
    assert exc_info.value is active
    assert "adapter-cleanup-fatal-secret" not in _secaware_traceback_locals(active)


def test_request_revalidation_failure_releases_prompt_from_frames() -> None:
    secret = "request-revalidation-prompt-secret"
    forged = _requests()[0].model_copy(update={"prompt": secret})
    with pytest.raises(Exception) as exc_info:
        revalidate_generation_request_envelope(forged)
    assert secret not in _secaware_traceback_locals(exc_info.value)


@pytest.mark.parametrize("signal_type", [MemoryError, KeyboardInterrupt, SystemExit])
def test_request_revalidation_preserves_fatal_identity_and_releases_prompt(
    monkeypatch: pytest.MonkeyPatch,
    signal_type: type[BaseException],
) -> None:
    secret = f"request-revalidation-{signal_type.__name__}-secret"
    forged = _requests()[0].model_copy(update={"prompt": secret})
    signal = signal_type("request-revalidation-control-flow")

    def fail_shape(_value):
        raise signal

    monkeypatch.setattr(generation_schema, "model_shape_is_intact", fail_shape)
    with pytest.raises(signal_type) as exc_info:
        revalidate_generation_request_envelope(forged)
    assert exc_info.value is signal
    assert secret not in _secaware_traceback_locals(signal)


@pytest.mark.parametrize("signal_type", [MemoryError, KeyboardInterrupt, SystemExit])
def test_confirmation_executor_preserves_fatal_identity_and_releases_frames(
    signal_type: type[BaseException],
) -> None:
    provider_secret = f"confirmation-{signal_type.__name__}-provider-secret"
    signal = signal_type("confirmation-control-flow")

    class Provider:
        def __repr__(self) -> str:
            return provider_secret

        def generate_many(self, _values):
            raise signal

    with pytest.raises(signal_type) as exc_info:
        execute_confirmation_requests((_requests()[0],), Provider())
    assert exc_info.value is signal
    assert provider_secret not in _secaware_traceback_locals(signal)


def test_confirmation_jsonl_parser_releases_invalid_payload_from_frames() -> None:
    secret = "confirmation-jsonl-parser-secret"
    with pytest.raises(SecAwareError) as exc_info:
        confirmation_stage._parse_jsonl(
            ('{"secret":"' + secret + '",}').encode(),
            GenerationRequestRecord,
            allow_empty=False,
        )
    assert secret not in _secaware_traceback_locals(exc_info.value)


@pytest.mark.parametrize("signal_type", [MemoryError, KeyboardInterrupt, SystemExit])
def test_confirmation_jsonl_parser_preserves_fatal_identity_and_releases_payload(
    signal_type: type[BaseException],
) -> None:
    secret = f"confirmation-jsonl-{signal_type.__name__}-secret"
    signal = signal_type("jsonl-control-flow")

    class FatalModel:
        @classmethod
        def model_validate(cls, _value):
            raise signal

    with pytest.raises(signal_type) as exc_info:
        confirmation_stage._parse_jsonl(
            ('{"value":"' + secret + '"}').encode(),
            FatalModel,
            allow_empty=False,
        )
    assert exc_info.value is signal
    assert secret not in _secaware_traceback_locals(signal)


def test_confirmation_generation_stage_declares_exact_atomic_outputs() -> None:
    assert "provider" not in inspect.signature(run_confirmation_generation_stage).parameters
    assert CONFIRMATION_GENERATION_OUTPUTS == (
        ("confirmation_requests.jsonl", GenerationRequestRecord),
        ("confirmation_execution.jsonl", AssignmentExecutionRecord),
        ("confirmation_code.jsonl", CanonicalGeneratedCodeRecord),
    )
    assert {
        "app_config_schema",
        "generation_config_schema",
        "request_schema",
        "code_schema",
        "execution_schema",
        "assignment_schema",
        "variant_schema",
        "randomization_manifest_schema",
        "producer_manifest_schema",
        "provider_policy_version",
        "provider_factory_version",
        "provider_response_contract_version",
        "provider_provenance_schema",
    } <= set(stage_contracts.confirmation_generation_stage_contract_payload())
    callable_bundle = stage_contracts.confirmation_generation_stage_contract_payload()[
        "runtime_callable_bundle"
    ]
    assert isinstance(callable_bundle, dict)
    assert "provider.from_frozen_config" in callable_bundle
    assert {
        "module",
        "qualname",
        "source_sha256",
        "code_sha256",
        "defaults_sha256",
        "closure_sha256",
        "partial_sha256",
        "callable_class_sha256",
        "fingerprint_sha256",
        "kind",
    } == set(callable_bundle["provider.from_frozen_config"])
    assert stage_contracts.confirmation_generation_stage_contract_payload()["output_policy"] == {
        "jsonl_max_line_chars": 4_000_000,
        "jsonl_max_total_chars": 240 * 1024 * 1024,
        "canonical_code_projection_version": "empty-skeleton-v1",
        "execution_record_overhead_chars": 4 * 1024,
        "json_string_max_expansion": 6,
        "provider_provenance_max_bytes": 4_096,
    }


def test_runtime_callable_descriptor_binds_closure_without_rendering_objects() -> None:
    class UnsafeRepresentation:
        def __repr__(self) -> str:
            raise AssertionError("closure object was rendered")

    def bind(value):
        def target():
            return value

        return target

    first = confirmation_stage._runtime_callable_descriptor(bind("first"))
    second = confirmation_stage._runtime_callable_descriptor(bind("second"))
    opaque = confirmation_stage._runtime_callable_descriptor(bind(UnsafeRepresentation()))
    assert first["closure_sha256"] != second["closure_sha256"]
    assert len(opaque["closure_sha256"]) == 64


@pytest.mark.parametrize(
    ("callable_class", "member_name"),
    (
        (confirmation_stage._LockedMockProvider, "generate_many"),
        (confirmation_stage._SingleRequestProviderAdapter, "generate_many"),
        (confirmation_stage._LockedMockProvider, "__init__"),
        (confirmation_stage.JsonlOutputSpec, "__init__"),
    ),
)
def test_runtime_callable_descriptor_binds_class_behavior_members_and_restores_stably(
    monkeypatch: pytest.MonkeyPatch,
    callable_class: type,
    member_name: str,
) -> None:
    baseline = confirmation_stage._runtime_callable_descriptor(callable_class)
    original = getattr(callable_class, member_name)

    @functools.wraps(original)
    def drifted(*args, **kwargs):
        return original(*args, **kwargs)

    with monkeypatch.context() as patcher:
        patcher.setattr(callable_class, member_name, drifted)
        assert confirmation_stage._runtime_callable_descriptor(callable_class) != baseline
    assert confirmation_stage._runtime_callable_descriptor(callable_class) == baseline


def test_runtime_callable_descriptor_binds_every_supported_class_descriptor_kind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class CallableBehavior:
        def __init__(self) -> None:
            self.value = 1

        def __call__(self) -> int:
            return self.value

        def ordinary(self) -> int:
            return self.value

        @staticmethod
        def static() -> int:
            return 1

        @classmethod
        def class_level(cls) -> str:
            return cls.__name__

        @property
        def property_value(self) -> int:
            return self.value

    baseline = confirmation_stage._runtime_callable_descriptor(CallableBehavior)
    replacements = {
        "__init__": lambda self: setattr(self, "value", 2),
        "__call__": lambda self: self.value + 1,
        "ordinary": lambda self: self.value + 1,
        "static": staticmethod(lambda: 2),
        "class_level": classmethod(lambda cls: cls.__qualname__),
        "property_value": property(lambda self: self.value + 1),
    }
    for name, replacement in replacements.items():
        with monkeypatch.context() as patcher:
            patcher.setattr(CallableBehavior, name, replacement)
            assert confirmation_stage._runtime_callable_descriptor(CallableBehavior) != baseline
        assert confirmation_stage._runtime_callable_descriptor(CallableBehavior) == baseline


@pytest.mark.parametrize(
    ("alias", "bundle_key"),
    (
        ("_guard_no_oracle_or_analysis", "input.guard_no_oracle_or_analysis"),
        ("_parse_jsonl", "input.parse_jsonl"),
        ("_parse_manifest", "input.parse_manifest"),
        ("_read_snapshot", "input.read_snapshot"),
        ("iter_bounded_tree", "input.bounded_tree"),
        ("model_shape_is_intact", "input.model_shape_is_intact"),
        ("RunStore", "input.run_store_factory"),
        ("_validate_producer_manifests", "input.validate_producer_manifests"),
        ("_validate_randomization_closure", "input.validate_randomization_closure"),
        ("plan_confirmation_requests", "planning.plan_confirmation_requests"),
        ("_SingleRequestProviderAdapter", "provider.adapter_factory"),
        (
            "create_openai_compatible_provider",
            "provider.create_openai_compatible_provider",
        ),
        ("_PROVIDER_RESULT_ENVELOPE_FACTORY", "provider.envelope_factory"),
        ("_provider_from_frozen_config", "provider.from_frozen_config"),
        ("_LockedMockProvider", "provider.mock_factory"),
        ("OpenAICompatibleGenerationResult", "provider.result_type"),
        (
            "execute_confirmation_requests",
            "execution.execute_confirmation_requests",
        ),
        ("_validate_output_bundle", "validation.output_bundle"),
        (
            "provider_provenance_sha256",
            "validation.provider_provenance_sha256",
        ),
        (
            "execute_jsonl_stage_transaction",
            "transaction.execute_jsonl_stage_transaction",
        ),
        ("JsonlOutputSpec", "transaction.jsonl_output_spec"),
        ("read_jsonl", "transaction.read_jsonl"),
    ),
)
def test_runtime_callable_bundle_binds_every_critical_stage_alias(
    randomized_store,
    monkeypatch: pytest.MonkeyPatch,
    alias: str,
    bundle_key: str,
) -> None:
    config, store = randomized_store
    run_confirmation_generation_stage(config, store, force=False)
    baseline = stage_contracts.confirmation_generation_stage_contract_payload()[
        "runtime_callable_bundle"
    ]
    original = getattr(confirmation_stage, alias)

    @functools.wraps(original)
    def drifted(*args, **kwargs):
        return original(*args, **kwargs)

    monkeypatch.setattr(confirmation_stage, alias, drifted)
    changed = stage_contracts.confirmation_generation_stage_contract_payload()[
        "runtime_callable_bundle"
    ]
    assert changed[bundle_key] != baseline[bundle_key]
    inputs = (
        *(store.path("interventions", name) for name, _model in PROMPT_VARIANT_OUTPUTS),
        store.path(".stages", "build-confirmation-variants.json"),
        *(store.path("interventions", name) for name, _model in RANDOMIZATION_OUTPUTS),
        store.path(".stages", "randomize-confirmation.json"),
    )
    outputs = tuple(
        store.path("generation", name) for name, _model in CONFIRMATION_GENERATION_OUTPUTS
    )
    try:
        assert not store.should_skip_stage("generate-confirmation", inputs, outputs, False)
    finally:
        store.abort_stage("generate-confirmation")


def test_generated_code_and_execution_ids_bind_actual_code_content() -> None:
    request = _requests()[0]

    class ProviderA:
        def generate_many(self, _requests):
            return ((request.request_id, _envelope(request, "first code\n")),)

    class ProviderB:
        def generate_many(self, _requests):
            return ((request.request_id, _envelope(request, "second code\n")),)

    first_executions, first_codes = execute_confirmation_requests((request,), ProviderA())
    second_executions, second_codes = execute_confirmation_requests((request,), ProviderB())
    assert first_codes[0].code_id != second_codes[0].code_id
    assert first_executions[0].execution_id != second_executions[0].execution_id


@pytest.mark.parametrize(
    "mutation", ["duplicate_code", "omit_code", "code_for_terminal", "omit_execution"]
)
def test_persisted_bundle_rejects_duplicate_omit_extra_and_bidirectional_subset(
    randomized_store,
    mutation: str,
) -> None:
    config, store = randomized_store
    snapshot, groups = _persisted_bundle(config, store)
    requests, executions, codes = groups
    mutated_executions = list(executions)
    mutated_codes = list(codes)
    if mutation == "duplicate_code":
        mutated_codes.append(mutated_codes[0])
    elif mutation == "omit_code":
        mutated_codes.pop()
    elif mutation == "omit_execution":
        mutated_executions.pop()
    else:
        first = mutated_executions[0]
        mutated_executions[0] = AssignmentExecutionRecord.from_content(
            assignment_id=first.assignment_id,
            request_id=first.request_id,
            status=AssignmentExecutionStatus.TERMINAL_NO_CODE,
            code_id=None,
            code_sha256=None,
            terminal_reason="content_filter",
            provider_result_sha256=first.provider_result_sha256,
            provider_provenance_sha256=first.provider_provenance_sha256,
            provider_runtime_sha256=first.provider_runtime_sha256,
            provider_policy_sha256=first.provider_policy_sha256,
            usage_sha256=first.usage_sha256,
            attempt_count=first.attempt_count,
        )
    with pytest.raises(SecAwareError):
        confirmation_stage._validate_output_bundle(
            snapshot, config, (requests, tuple(mutated_executions), tuple(mutated_codes))
        )


@pytest.mark.parametrize("group", ("executions", "codes"))
def test_persisted_bundle_requires_exact_canonical_sequence_order(
    randomized_store,
    group: str,
) -> None:
    config, store = randomized_store
    snapshot, groups = _persisted_bundle(config, store)
    requests, executions, codes = groups
    mutated = (
        requests,
        tuple(reversed(executions)) if group == "executions" else executions,
        tuple(reversed(codes)) if group == "codes" else codes,
    )
    with pytest.raises(SecAwareError):
        confirmation_stage._validate_output_bundle(snapshot, config, mutated)


def test_output_bundle_failure_releases_snapshot_prompt_and_code_from_frames(
    randomized_store,
) -> None:
    config, store = randomized_store
    snapshot, groups = _persisted_bundle(config, store)
    prompt_secret = snapshot.variants[0].prompt_text
    code_secret = groups[2][0].code
    with pytest.raises(SecAwareError) as exc_info:
        confirmation_stage._validate_output_bundle(
            snapshot,
            config,
            (groups[0], tuple(reversed(groups[1])), groups[2]),
        )
    retained = _secaware_traceback_locals(exc_info.value)
    assert prompt_secret not in retained
    assert code_secret not in retained


@pytest.mark.parametrize("signal_type", [MemoryError, KeyboardInterrupt, SystemExit])
def test_output_bundle_preserves_fatal_identity_and_releases_snapshot(
    randomized_store,
    signal_type: type[BaseException],
) -> None:
    config, store = randomized_store
    snapshot, groups = _persisted_bundle(config, store)
    prompt_secret = snapshot.variants[0].prompt_text
    code_secret = groups[2][0].code
    signal = signal_type("output-bundle-control-flow")

    def fail_plan(*_args, **_kwargs):
        raise signal

    with pytest.raises(signal_type) as exc_info:
        confirmation_stage._validate_output_bundle(
            snapshot,
            config,
            groups,
            planner=fail_plan,
        )
    assert exc_info.value is signal
    retained = _secaware_traceback_locals(signal)
    assert prompt_secret not in retained
    assert code_secret not in retained


@pytest.mark.parametrize("drift", ["assignment_id", "arm", "seed", "protocol", "variant"])
def test_legally_resealed_assignment_coordinate_drift_breaks_frozen_manifest(
    randomized_store,
    drift: str,
) -> None:
    config, store = randomized_store
    snapshot, _groups = _persisted_bundle(config, store)
    assignments = list(snapshot.assignments)
    original = assignments[0]
    content = original.model_dump(mode="python", exclude={"assignment_id", "schema_version"})
    if drift == "assignment_id":
        content["randomization_plan_sha256"] = "e" * 64
    elif drift == "arm":
        content["arm_role"] = next(role for role in ArmRole if role is not original.arm_role)
    elif drift == "seed":
        content["seed_id"] = original.seed_id + 1
    elif drift == "variant":
        content["variant_id"] = next(
            item.variant_id for item in assignments[1:] if item.variant_id != original.variant_id
        )
    else:
        content["arm_protocol_id"] = "arm_protocol_" + "f" * 64
        unit = original.experimental_unit
        content["block_id"] = AssignmentRecord.block_id_from_key(
            unit.task_id,
            unit.hypothesis_id,
            unit.target_spec_id,
            content["arm_protocol_id"],
            unit.model_id,
        )
    replacement = AssignmentRecord.from_content(**content)
    assert replacement.assignment_id != original.assignment_id
    assignments[0] = replacement
    with pytest.raises(SecAwareError):
        confirmation_stage._validate_randomization_closure(
            snapshot.randomization_manifest, tuple(assignments)
        )


def test_confirmation_generation_fingerprint_binds_config_schema_and_provider_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_config("configs/demo.yaml")
    inputs = {"interventions/assignments.jsonl": "a" * 64}

    def fingerprint(value):
        return build_stage_fingerprint(
            "generate-confirmation",
            inputs,
            value.model_dump(mode="json"),
            stage_contract_sha256=stage_contracts.confirmation_generation_stage_contract_sha256(
                "generate-confirmation"
            ),
            code_version=__version__,
        )

    baseline = fingerprint(config)
    payload = config.model_dump(mode="json")
    payload["generation"]["confirmation_seeds"] = list(range(201, 213))
    changed_config = type(config).model_validate(payload)
    assert fingerprint(changed_config) != baseline

    original_contract = stage_contracts.confirmation_generation_stage_contract_sha256(
        "generate-confirmation"
    )
    monkeypatch.setattr(
        confirmation_stage,
        "CONFIRMATION_PROVIDER_POLICY_VERSION",
        "future-provider-policy",
    )
    assert (
        stage_contracts.confirmation_generation_stage_contract_sha256("generate-confirmation")
        != original_contract
    )
    monkeypatch.setattr(
        confirmation_stage,
        "CONFIRMATION_PROVIDER_POLICY_VERSION",
        "assignment-bound-generation-provider-v1",
    )
    original_schema_digest = stage_contracts._schema_sha256

    def drift_request_schema(model: type) -> str:
        if model is GenerationRequestRecord:
            return "f" * 64
        return original_schema_digest(model)

    monkeypatch.setattr(stage_contracts, "_schema_sha256", drift_request_schema)
    assert (
        stage_contracts.confirmation_generation_stage_contract_sha256("generate-confirmation")
        != original_contract
    )


def test_openai_runtime_contract_binds_actual_sdk_and_source_digests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generation = GenerationConfig(
        provider="openai_compatible",
        models=["model-a"],
        seeds=[1],
        confirmation_seeds=[101],
        openai_compatible=OpenAICompatibleConfig(base_url="https://example.test/v1"),
    )
    monkeypatch.setattr(
        openai_provider.importlib.metadata,
        "version",
        lambda package: "1.2.3" if package == "openai" else "unknown",
    )
    payload = stage_contracts.confirmation_generation_stage_contract_payload(generation)
    runtime = payload["provider_runtime"]
    assert isinstance(runtime, dict)
    assert runtime["openai_sdk_version"] == "1.2.3"
    assert {
        "provider_source_sha256",
        "factory_source_sha256",
        "response_source_sha256",
        "usage_source_sha256",
    } <= set(runtime)
    baseline = stage_contracts.confirmation_generation_stage_contract_sha256(
        "generate-confirmation", generation
    )
    monkeypatch.setattr(
        openai_provider.importlib.metadata,
        "version",
        lambda package: "9.9.9" if package == "openai" else "unknown",
    )
    assert (
        stage_contracts.confirmation_generation_stage_contract_sha256(
            "generate-confirmation", generation
        )
        != baseline
    )


def test_confirmation_generation_stage_publishes_exact_assignment_coverage(
    randomized_store,
) -> None:
    config, store = randomized_store
    result = run_confirmation_generation_stage(config, store, force=False)
    requests = read_jsonl(
        store.path("generation", "confirmation_requests.jsonl"),
        GenerationRequestRecord,
        required=True,
        allow_empty=False,
    )
    assert result.assignment_count == len(requests)
    assert result.generated_count == result.assignment_count
    assert result.terminal_no_code_count == 0


@pytest.mark.parametrize("mutation", ("request_id", "prompt_sha256"))
def test_confirmation_stage_rejects_independent_request_identity_mutation(
    randomized_store,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    config, store = randomized_store
    real_plan = confirmation_stage.plan_confirmation_requests

    def forged_plan(*args, **kwargs):
        records = real_plan(*args, **kwargs)
        request = records[0]
        if mutation == "request_id":
            forged = request.model_copy(update={"request_id": "req_" + "f" * 64})
        else:
            forged_hash = "e" * 64
            identity = request.model_dump(mode="python", exclude={"request_id", "prompt"})
            identity["prompt_sha256"] = forged_hash
            identity["parameters"] = request.parameters
            forged = request.model_copy(
                update={
                    "prompt_sha256": forged_hash,
                    "request_id": build_generation_request_id(**identity),
                }
            )
        return [forged, *records[1:]]

    monkeypatch.setattr(confirmation_stage, "plan_confirmation_requests", forged_plan)
    with pytest.raises(SecAwareError):
        run_confirmation_generation_stage(config, store, force=True)


def test_confirmation_generation_stage_force_partial_install_restores_old_commit(
    randomized_store,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = randomized_store
    run_confirmation_generation_stage(config, store, force=False)
    outputs = tuple(
        store.path("generation", name) for name, _model in CONFIRMATION_GENERATION_OUTPUTS
    )
    manifest = store.path(".stages", "generate-confirmation.json")
    before = tuple(path.read_bytes() for path in (*outputs, manifest))
    real_install = ArtifactTransaction.install

    def fail_partial(self, index, candidate):
        if self.journal_path.name == ".generate-confirmation.transaction.json" and index == 1:
            raise TransactionStateError()
        return real_install(self, index, candidate)

    monkeypatch.setattr(ArtifactTransaction, "install", fail_partial)
    with pytest.raises(SecAwareError):
        run_confirmation_generation_stage(config, store, force=True)
    assert tuple(path.read_bytes() for path in (*outputs, manifest)) == before


@pytest.mark.parametrize("signal_type", [MemoryError, KeyboardInterrupt, SystemExit])
def test_confirmation_stage_preserves_fatal_identity_cleans_frames_and_old_commit(
    randomized_store,
    monkeypatch: pytest.MonkeyPatch,
    signal_type: type[BaseException],
) -> None:
    config, store = randomized_store
    run_confirmation_generation_stage(config, store, force=False)
    outputs = tuple(
        store.path("generation", name) for name, _model in CONFIRMATION_GENERATION_OUTPUTS
    )
    before = tuple(path.read_bytes() for path in outputs)
    provider_secret = f"stage-{signal_type.__name__}-provider-secret"
    signal = signal_type("stage-control-flow")

    class Provider:
        def __repr__(self) -> str:
            return provider_secret

        def generate_many(self, _requests):
            raise signal

    monkeypatch.setattr(
        confirmation_stage,
        "_provider_from_frozen_config",
        lambda _config, **_kwargs: Provider(),
    )
    with pytest.raises(signal_type) as exc_info:
        run_confirmation_generation_stage(config, store, force=True)
    assert exc_info.value is signal
    assert provider_secret not in _secaware_traceback_locals(signal)
    assert tuple(path.read_bytes() for path in outputs) == before


def test_confirmation_stage_capture_releases_snapshotted_payloads_on_failure(
    randomized_store,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = randomized_store
    secret = read_jsonl(
        store.path("interventions", "prompt_variants.jsonl"),
        confirmation_stage.PromptVariantRecord,
        required=True,
        allow_empty=False,
    )[0].prompt_text

    def reject(*_args, **_kwargs):
        raise SecAwareError(code=3, stage="capture-test", message="capture failed")

    monkeypatch.setattr(confirmation_stage, "_parse_jsonl", reject)
    with pytest.raises(SecAwareError) as exc_info:
        run_confirmation_generation_stage(config, store, force=True)
    assert secret not in _secaware_traceback_locals(exc_info.value)


@pytest.mark.parametrize("signal_type", [MemoryError, KeyboardInterrupt, SystemExit])
def test_confirmation_stage_capture_preserves_fatal_identity_and_releases_payloads(
    randomized_store,
    monkeypatch: pytest.MonkeyPatch,
    signal_type: type[BaseException],
) -> None:
    config, store = randomized_store
    secret = read_jsonl(
        store.path("interventions", "prompt_variants.jsonl"),
        confirmation_stage.PromptVariantRecord,
        required=True,
        allow_empty=False,
    )[0].prompt_text
    signal = signal_type("capture-control-flow")

    def interrupt(*_args, **_kwargs):
        raise signal

    monkeypatch.setattr(confirmation_stage, "_parse_jsonl", interrupt)
    with pytest.raises(signal_type) as exc_info:
        run_confirmation_generation_stage(config, store, force=True)
    assert exc_info.value is signal
    assert secret not in _secaware_traceback_locals(signal)


def test_confirmation_stage_verify_releases_replaced_input_payload_from_frames(
    randomized_store,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = randomized_store
    secret = read_jsonl(
        store.path("interventions", "prompt_variants.jsonl"),
        PromptVariantRecord,
        required=True,
        allow_empty=False,
    )[0].prompt_text
    input_count = len(PROMPT_VARIANT_OUTPUTS) + len(RANDOMIZATION_OUTPUTS) + 2
    calls = 0
    real_read = confirmation_stage._read_snapshot

    def replace_variant_identity(path, *, allow_empty):
        nonlocal calls
        calls += 1
        payload, current = real_read(path, allow_empty=allow_empty)
        if calls == input_count + 9:
            current = replace(current, identity=(*current.identity[:-1], current.identity[-1] + 1))
        return payload, current

    monkeypatch.setattr(confirmation_stage, "_read_snapshot", replace_variant_identity)
    with pytest.raises(SecAwareError) as exc_info:
        run_confirmation_generation_stage(config, store, force=True)

    assert secret not in _secaware_traceback_locals(exc_info.value)


@pytest.mark.parametrize("signal_type", [MemoryError, KeyboardInterrupt, SystemExit])
def test_confirmation_stage_verify_later_fatal_preserves_identity_and_releases_prior_payload(
    randomized_store,
    monkeypatch: pytest.MonkeyPatch,
    signal_type: type[BaseException],
) -> None:
    config, store = randomized_store
    secret = read_jsonl(
        store.path("interventions", "prompt_variants.jsonl"),
        PromptVariantRecord,
        required=True,
        allow_empty=False,
    )[0].prompt_text
    input_count = len(PROMPT_VARIANT_OUTPUTS) + len(RANDOMIZATION_OUTPUTS) + 2
    calls = iter(range(1, input_count + 11))
    signal = signal_type("verify-input-control-flow")
    real_read = confirmation_stage._read_snapshot

    def interrupt_after_variant(path, *, allow_empty):
        if next(calls) == input_count + 10:
            raise signal
        return real_read(path, allow_empty=allow_empty)

    monkeypatch.setattr(confirmation_stage, "_read_snapshot", interrupt_after_variant)
    with pytest.raises(signal_type) as exc_info:
        run_confirmation_generation_stage(config, store, force=True)

    assert exc_info.value is signal
    assert secret not in _secaware_traceback_locals(signal)


def test_confirmation_generation_stage_skips_valid_commit_and_repairs_tamper(
    randomized_store,
) -> None:
    config, store = randomized_store

    monkeypatch = pytest.MonkeyPatch()
    skipped = run_confirmation_generation_stage(config, store, force=False)
    assert skipped.assignment_count > 0
    code_path = store.path("generation", "confirmation_code.jsonl")
    code_path.write_bytes(code_path.read_bytes() + b"{}\n")
    monkeypatch.setattr(
        confirmation_stage,
        "_provider_from_frozen_config",
        lambda _config, **_kwargs: _Provider(),
    )
    repaired = run_confirmation_generation_stage(config, store, force=False)
    monkeypatch.undo()
    assert repaired.generated_count == repaired.assignment_count


def test_confirmation_generation_rejects_future_oracle_artifact_and_preserves_commit(
    randomized_store,
) -> None:
    config, store = randomized_store
    run_confirmation_generation_stage(config, store, force=False)
    outputs = tuple(
        store.path("generation", name) for name, _model in CONFIRMATION_GENERATION_OUTPUTS
    )
    before = tuple(path.read_bytes() for path in outputs)
    future = store.path("oracle", "confirmation_oracle.jsonl")
    future.write_text("{}\n", encoding="utf-8")
    try:
        with pytest.raises(SecAwareError):
            run_confirmation_generation_stage(config, store, force=True)
    finally:
        future.unlink()
    assert tuple(path.read_bytes() for path in outputs) == before


def test_confirmation_generation_stage_infrastructure_abort_publishes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, store = _stage_store(tmp_path, task_count=20)
    run_prompt_variant_freeze_stage(config, store, force=False)
    run_confirmation_randomization_stage(config, store, force=False)

    class FailingProvider:
        def generate_many(self, _requests):
            raise RuntimeError("authorization secret")

    monkeypatch.setattr(
        confirmation_stage,
        "_provider_from_frozen_config",
        lambda _config, **_kwargs: FailingProvider(),
    )
    with pytest.raises(SecAwareError) as caught:
        run_confirmation_generation_stage(config, store, force=False)
    assert "authorization secret" not in str(caught.value)
    assert all(
        not store.path("generation", name).exists()
        for name, _model in CONFIRMATION_GENERATION_OUTPUTS
    )


@pytest.mark.parametrize(
    ("case", "expected_code"),
    (
        ("none", ErrorCode.CONFIG),
        ("auth", ErrorCode.API_AUTH),
        ("endpoint", ErrorCode.CONFIG),
        ("model", ErrorCode.API_INVALID_RESPONSE),
        ("malformed", ErrorCode.API_INVALID_RESPONSE),
        ("transport", ErrorCode.API_INVALID_RESPONSE),
        ("timeout", ErrorCode.API_TIMEOUT),
        ("retry_exhausted", ErrorCode.API_RETRIES_EXHAUSTED),
    ),
)
def test_confirmation_stage_all_infrastructure_failures_preserve_force_commit(
    randomized_store,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    expected_code: ErrorCode,
) -> None:
    config, store = randomized_store
    run_confirmation_generation_stage(config, store, force=False)
    paths = tuple(
        store.path("generation", name) for name, _model in CONFIRMATION_GENERATION_OUTPUTS
    )
    manifest = store.path(".stages", "generate-confirmation.json")
    before = tuple(path.read_bytes() for path in (*paths, manifest))

    class FailingProvider:
        def generate_many(self, _requests):
            if case == "malformed":
                return (("req_" + "f" * 64, object()),)
            raise SecAwareError(
                code=expected_code,
                stage="provider-test",
                message="safe provider failure",
            )

    def factory(_config, **_kwargs):
        if case in {"none", "endpoint"}:
            raise SecAwareError(
                code=expected_code,
                stage="provider-factory-test",
                message="provider unavailable",
            )
        return FailingProvider()

    monkeypatch.setattr(confirmation_stage, "_provider_from_frozen_config", factory)
    with pytest.raises(SecAwareError) as exc_info:
        run_confirmation_generation_stage(config, store, force=True)
    assert exc_info.value.code is expected_code
    assert tuple(path.read_bytes() for path in (*paths, manifest)) == before


@pytest.mark.parametrize("drift", ["config", "schema", "provider_policy", "factory_alias"])
def test_valid_committed_skip_is_invalidated_by_every_bound_contract_drift(
    randomized_store,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    config, store = randomized_store
    run_confirmation_generation_stage(config, store, force=False)
    calls = 0

    class CountingProvider(_Provider):
        def generate_many(self, requests):
            nonlocal calls
            calls += 1
            return super().generate_many(requests)

    effective_config = config
    effective_store = store
    if drift == "config":
        payload = config.model_dump(mode="python")
        payload["generation"]["models"] = ["contract-drift-model"]
        effective_config = type(config).model_validate(payload)
        effective_store = type(store)(effective_config)
    elif drift == "schema":
        original = stage_contracts._schema_sha256

        def drift_schema(model):
            if model is GenerationRequestRecord:
                return "d" * 64
            return original(model)

        monkeypatch.setattr(stage_contracts, "_schema_sha256", drift_schema)
    elif drift == "provider_policy":
        monkeypatch.setattr(
            confirmation_stage,
            "CONFIRMATION_PROVIDER_POLICY_VERSION",
            "provider-policy-drift-test",
        )
    else:

        def drifted_factory(_config, **_kwargs):
            return CountingProvider()

        monkeypatch.setattr(
            confirmation_stage,
            "_provider_from_frozen_config",
            drifted_factory,
        )
    if drift != "factory_alias":
        monkeypatch.setattr(
            confirmation_stage,
            "_provider_from_frozen_config",
            lambda _config, **_kwargs: CountingProvider(),
        )
    if drift == "config":
        with pytest.raises(SecAwareError) as exc_info:
            run_confirmation_generation_stage(effective_config, effective_store, force=False)
        assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
        assert calls == 0
        return
    result = run_confirmation_generation_stage(effective_config, effective_store, force=False)
    assert calls == result.assignment_count


def test_provider_factory_alias_change_after_capture_aborts_and_preserves_commit(
    randomized_store,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = randomized_store
    run_confirmation_generation_stage(config, store, force=False)
    paths = tuple(
        store.path("generation", name) for name, _model in CONFIRMATION_GENERATION_OUTPUTS
    )
    manifest = store.path(".stages", "generate-confirmation.json")
    before = tuple(path.read_bytes() for path in (*paths, manifest))

    def replacement_factory(_config, **_kwargs):
        return _Provider()

    class MutatingProvider(_Provider):
        def generate_many(self, requests):
            result = super().generate_many(requests)
            monkeypatch.setattr(
                confirmation_stage,
                "_provider_from_frozen_config",
                replacement_factory,
            )
            return result

    def captured_factory(_config, **_kwargs):
        return MutatingProvider()

    monkeypatch.setattr(
        confirmation_stage,
        "_provider_from_frozen_config",
        captured_factory,
    )
    with pytest.raises(SecAwareError):
        run_confirmation_generation_stage(config, store, force=True)
    assert tuple(path.read_bytes() for path in (*paths, manifest)) == before


def test_class_drift_during_provider_construction_aborts_before_executor_and_preserves_commit(
    randomized_store,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = randomized_store
    run_confirmation_generation_stage(config, store, force=False)
    paths = tuple(
        store.path("generation", name) for name, _model in CONFIRMATION_GENERATION_OUTPUTS
    )
    manifest = store.path(".stages", "generate-confirmation.json")
    before = tuple(path.read_bytes() for path in (*paths, manifest))
    provider_type = confirmation_stage._LockedMockProvider
    original_init = provider_type.__init__
    original_generate = provider_type.generate_many
    generate_calls = 0

    @functools.wraps(original_generate)
    def drifted_generate(self, requests):
        nonlocal generate_calls
        generate_calls += 1
        return original_generate(self, requests)

    @functools.wraps(original_init)
    def mutating_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        monkeypatch.setattr(provider_type, "generate_many", drifted_generate)

    monkeypatch.setattr(provider_type, "__init__", mutating_init)
    monkeypatch.setattr(
        confirmation_stage,
        "_provider_from_frozen_config",
        lambda _config, **kwargs: provider_type(kwargs["envelope_factory"]),
    )
    with pytest.raises(SecAwareError):
        run_confirmation_generation_stage(config, store, force=True)
    assert generate_calls == 0
    assert tuple(path.read_bytes() for path in (*paths, manifest)) == before


def test_class_drift_during_executor_aborts_publish_and_preserves_commit(
    randomized_store,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = randomized_store
    run_confirmation_generation_stage(config, store, force=False)
    paths = tuple(
        store.path("generation", name) for name, _model in CONFIRMATION_GENERATION_OUTPUTS
    )
    manifest = store.path(".stages", "generate-confirmation.json")
    before = tuple(path.read_bytes() for path in (*paths, manifest))
    provider_type = confirmation_stage._LockedMockProvider
    original_init = provider_type.__init__
    original_generate = provider_type.generate_many

    @functools.wraps(original_init)
    def drifted_init(self, *args, **kwargs):
        return original_init(self, *args, **kwargs)

    @functools.wraps(original_generate)
    def mutating_generate(self, requests):
        result = original_generate(self, requests)
        monkeypatch.setattr(provider_type, "__init__", drifted_init)
        return result

    monkeypatch.setattr(provider_type, "generate_many", mutating_generate)
    monkeypatch.setattr(
        confirmation_stage,
        "_provider_from_frozen_config",
        lambda _config, **kwargs: provider_type(kwargs["envelope_factory"]),
    )
    with pytest.raises(SecAwareError):
        run_confirmation_generation_stage(config, store, force=True)
    assert tuple(path.read_bytes() for path in (*paths, manifest)) == before


def test_assignment_manifest_replacement_during_provider_call_aborts_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, store = _stage_store(tmp_path, task_count=20)
    run_prompt_variant_freeze_stage(config, store, force=False)
    run_confirmation_randomization_stage(config, store, force=False)
    assignment_path = store.path("interventions", "assignments.jsonl")

    class ReplacingProvider(_Provider):
        def generate_many(self, requests):
            replacement = assignment_path.with_suffix(".replacement")
            replacement.write_bytes(assignment_path.read_bytes())
            os.replace(replacement, assignment_path)
            return super().generate_many(requests)

    monkeypatch.setattr(
        confirmation_stage,
        "_provider_from_frozen_config",
        lambda _config, **_kwargs: ReplacingProvider(),
    )
    with pytest.raises(SecAwareError):
        run_confirmation_generation_stage(config, store, force=False)
    assert all(
        not store.path("generation", name).exists()
        for name, _model in CONFIRMATION_GENERATION_OUTPUTS
    )


@pytest.mark.parametrize(
    "source_path",
    (
        ("prompt_variants.jsonl",),
        ("assignments.jsonl",),
    ),
)
def test_task4_and_randomization_producer_replacement_leases_abort_force_commit(
    randomized_store,
    monkeypatch: pytest.MonkeyPatch,
    source_path: tuple[str],
) -> None:
    config, store = randomized_store
    run_confirmation_generation_stage(config, store, force=False)
    source = store.path("interventions", source_path[0])
    outputs = tuple(
        store.path("generation", name) for name, _model in CONFIRMATION_GENERATION_OUTPUTS
    )
    before = tuple(path.read_bytes() for path in outputs)

    class ReplacingProvider(_Provider):
        def generate_many(self, requests):
            replacement = source.with_suffix(source.suffix + ".replacement")
            replacement.write_bytes(source.read_bytes())
            os.replace(replacement, source)
            return super().generate_many(requests)

    monkeypatch.setattr(
        confirmation_stage,
        "_provider_from_frozen_config",
        lambda _config, **_kwargs: ReplacingProvider(),
    )
    with pytest.raises(SecAwareError):
        run_confirmation_generation_stage(config, store, force=True)
    assert tuple(path.read_bytes() for path in outputs) == before


def test_confirmation_generation_holds_both_real_producer_leases_through_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, setup_store = _stage_store(tmp_path, task_count=20)
    run_prompt_variant_freeze_stage(config, setup_store, force=False)
    run_confirmation_randomization_stage(config, setup_store, force=False)
    consumer_store = type(setup_store)(config)
    task4_writer = type(setup_store)(config)
    randomization_writer = type(setup_store)(config)
    entered_provider = threading.Event()
    release_provider = threading.Event()
    active: list[str] = []
    entered: list[str] = []
    committed_with_both_leases = False
    failures: list[BaseException] = []
    results = []
    store_type = type(setup_store)
    real_hold = store_type.hold_committed_output
    real_record_stage = store_type.record_stage

    @contextmanager
    def tracked_hold(self, stage, outputs, **kwargs):
        with real_hold(self, stage, outputs, **kwargs) as hashes:
            active.append(stage)
            entered.append(stage)
            try:
                yield hashes
            finally:
                active.remove(stage)

    def checked_record_stage(self, stage, *args, **kwargs):
        nonlocal committed_with_both_leases
        if stage == "generate-confirmation":
            committed_with_both_leases = active == [
                "build-confirmation-variants",
                "randomize-confirmation",
            ]
        return real_record_stage(self, stage, *args, **kwargs)

    class BarrierProvider(_Provider):
        def generate_many(self, requests):
            assert active == ["build-confirmation-variants", "randomize-confirmation"]
            entered_provider.set()
            assert release_provider.wait(timeout=30)
            return super().generate_many(requests)

    monkeypatch.setattr(store_type, "hold_committed_output", tracked_hold)
    monkeypatch.setattr(store_type, "record_stage", checked_record_stage)
    monkeypatch.setattr(
        confirmation_stage,
        "_provider_from_frozen_config",
        lambda _config, **_kwargs: BarrierProvider(),
    )

    def consume() -> None:
        try:
            results.append(run_confirmation_generation_stage(config, consumer_store, force=False))
        except BaseException as error:
            failures.append(error)

    thread = threading.Thread(target=consume)
    thread.start()
    assert entered_provider.wait(timeout=30), failures
    task4_paths = tuple(
        setup_store.path("interventions", name) for name, _model in PROMPT_VARIANT_OUTPUTS
    )
    randomization_paths = tuple(
        setup_store.path("interventions", name) for name, _model in RANDOMIZATION_OUTPUTS
    )
    assert len(task4_paths) == 11
    assert len(randomization_paths) == 2
    task4_manifest = setup_store.path(".stages", "build-confirmation-variants.json")
    randomization_manifest = setup_store.path(".stages", "randomize-confirmation.json")
    task4_snapshot = tuple(path.read_bytes() for path in (*task4_paths, task4_manifest))
    randomization_snapshot = tuple(
        path.read_bytes() for path in (*randomization_paths, randomization_manifest)
    )

    try:
        with pytest.raises(SecAwareError) as task4_error:
            run_prompt_variant_freeze_stage(config, task4_writer, force=True)
        with pytest.raises(SecAwareError) as randomization_error:
            run_confirmation_randomization_stage(config, randomization_writer, force=True)
        assert task4_error.value.code is ErrorCode.MANIFEST_CONFLICT
        assert randomization_error.value.code is ErrorCode.MANIFEST_CONFLICT
        assert task4_snapshot == tuple(path.read_bytes() for path in (*task4_paths, task4_manifest))
        assert randomization_snapshot == tuple(
            path.read_bytes() for path in (*randomization_paths, randomization_manifest)
        )
    finally:
        release_provider.set()
    thread.join(timeout=30)

    assert not thread.is_alive()
    assert failures == []
    assert len(results) == 1
    assert entered == ["build-confirmation-variants", "randomize-confirmation"]
    assert committed_with_both_leases is True
    assert active == []
    assert all(
        setup_store.path("generation", name).exists()
        for name, _model in CONFIRMATION_GENERATION_OUTPUTS
    )

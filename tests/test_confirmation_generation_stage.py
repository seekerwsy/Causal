from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import inspect
import os

import pytest

from secaware.errors import ErrorCode, SecAwareError
from secaware.config import load_config
from secaware.generation.confirmation import execute_confirmation_requests
from secaware.io.jsonl import read_jsonl
from secaware.io.transaction import ArtifactTransaction, TransactionStateError
from secaware.pipeline.stages.prompt_variants import run_prompt_variant_freeze_stage
from secaware.pipeline.stages.randomization import run_confirmation_randomization_stage
import secaware.pipeline.stage_contracts as stage_contracts
from secaware.pipeline.stages.confirmation_generation import (
    CONFIRMATION_GENERATION_OUTPUTS,
    run_confirmation_generation_stage,
)
import secaware.pipeline.stages.confirmation_generation as confirmation_stage
from secaware.pipeline.manifest import build_stage_fingerprint
from secaware import __version__
from secaware.schema.experiments import AssignmentExecutionRecord, AssignmentExecutionStatus
from secaware.schema.experiments import ArmRole, AssignmentRecord, PromptVariantRecord, RandomizationManifestRecord
from secaware.schema.generation import GenerationRequestRecord
from secaware.schema.generation import GenerationProvenance
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
                _Result(None, "content_filter")
                if item.assignment_id == self.content_filter_assignment
                else _Result(f"# code for {item.assignment_id}\n", "stop"),
            )
            for item in items
        )


@pytest.fixture(autouse=True)
def _locked_test_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        confirmation_stage, "_provider_from_frozen_config", lambda _config: _Provider()
    )


@pytest.fixture(scope="module")
def randomized_store(tmp_path_factory: pytest.TempPathFactory):
    config, store = _stage_store(tmp_path_factory.mktemp("confirmation-generation"), task_count=20)
    run_prompt_variant_freeze_stage(config, store, force=False)
    run_confirmation_randomization_stage(config, store, force=False)
    return config, store


def _requests():
    pairs = (_assignment_and_variant(task_id="task-a"), _assignment_and_variant(task_id="task-b"))
    return plan_confirmation_requests(
        tuple(item[0] for item in pairs), tuple(item[1] for item in pairs), _generation_config()
    )


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
    assert {item.assignment_id for item in records} == {
        item.assignment_id for item in requests
    }
    assert sum(item.status is AssignmentExecutionStatus.TERMINAL_NO_CODE for item in records) == 1
    assert len(codes) == len(records) - 1
    assert {item.assignment_id for item in codes} == {
        item.assignment_id
        for item in records
        if item.status is AssignmentExecutionStatus.GENERATED
    }


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
            ("{\"secret\":\"" + secret + "\",}").encode(),
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
            ("{\"value\":\"" + secret + "\"}").encode(),
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


def test_generated_code_and_execution_ids_bind_actual_code_content() -> None:
    request = _requests()[0]

    class ProviderA:
        def generate_many(self, _requests):
            return ((request.request_id, _Result("first code\n", "stop")),)

    class ProviderB:
        def generate_many(self, _requests):
            return ((request.request_id, _Result("second code\n", "stop")),)

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
        )
    with pytest.raises(SecAwareError):
        confirmation_stage._validate_output_bundle(
            snapshot, config, (requests, tuple(mutated_executions), tuple(mutated_codes))
        )


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
        stage_contracts.confirmation_generation_stage_contract_sha256(
            "generate-confirmation"
        )
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
        stage_contracts.confirmation_generation_stage_contract_sha256(
            "generate-confirmation"
        )
        != original_contract
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
        confirmation_stage, "_provider_from_frozen_config", lambda _config: Provider()
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


def test_confirmation_generation_stage_skips_valid_commit_and_repairs_tamper(
    randomized_store,
) -> None:
    config, store = randomized_store

    class ExplodingProvider:
        def generate_many(self, _requests):
            raise AssertionError("valid committed stage must skip provider")

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(
        confirmation_stage, "_provider_from_frozen_config", lambda _config: ExplodingProvider()
    )
    skipped = run_confirmation_generation_stage(config, store, force=False)
    assert skipped.assignment_count > 0
    code_path = store.path("generation", "confirmation_code.jsonl")
    code_path.write_bytes(code_path.read_bytes() + b"{}\n")
    monkeypatch.setattr(
        confirmation_stage, "_provider_from_frozen_config", lambda _config: _Provider()
    )
    repaired = run_confirmation_generation_stage(config, store, force=False)
    monkeypatch.undo()
    assert repaired.generated_count == repaired.assignment_count


def test_confirmation_generation_rejects_future_oracle_artifact_and_preserves_commit(
    randomized_store,
) -> None:
    config, store = randomized_store
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
        confirmation_stage, "_provider_from_frozen_config", lambda _config: FailingProvider()
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

    def factory(_config):
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


@pytest.mark.parametrize("drift", ["config", "schema", "provider_policy"])
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
    else:
        monkeypatch.setattr(
            confirmation_stage,
            "CONFIRMATION_PROVIDER_POLICY_VERSION",
            "provider-policy-drift-test",
        )
    monkeypatch.setattr(
        confirmation_stage, "_provider_from_frozen_config", lambda _config: CountingProvider()
    )
    if drift == "config":
        with pytest.raises(SecAwareError) as exc_info:
            run_confirmation_generation_stage(effective_config, effective_store, force=False)
        assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
        assert calls == 0
        return
    run_confirmation_generation_stage(effective_config, effective_store, force=False)
    assert calls == 1


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
        lambda _config: ReplacingProvider(),
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
        lambda _config: ReplacingProvider(),
    )
    with pytest.raises(SecAwareError):
        run_confirmation_generation_stage(config, store, force=True)
    assert tuple(path.read_bytes() for path in outputs) == before

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import os

import pytest

from secaware.errors import SecAwareError
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


def test_confirmation_generation_stage_declares_exact_atomic_outputs() -> None:
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
    } <= set(stage_contracts.confirmation_generation_stage_contract_payload())


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
    result = run_confirmation_generation_stage(config, store, force=False, provider=_Provider())
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
        run_confirmation_generation_stage(config, store, force=True, provider=_Provider())
    assert tuple(path.read_bytes() for path in (*outputs, manifest)) == before


def test_confirmation_generation_stage_skips_valid_commit_and_repairs_tamper(
    randomized_store,
) -> None:
    config, store = randomized_store

    class ExplodingProvider:
        def generate_many(self, _requests):
            raise AssertionError("valid committed stage must skip provider")

    skipped = run_confirmation_generation_stage(
        config, store, force=False, provider=ExplodingProvider()
    )
    assert skipped.assignment_count > 0
    code_path = store.path("generation", "confirmation_code.jsonl")
    code_path.write_bytes(code_path.read_bytes() + b"{}\n")
    repaired = run_confirmation_generation_stage(config, store, force=False, provider=_Provider())
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
            run_confirmation_generation_stage(config, store, force=True, provider=_Provider())
    finally:
        future.unlink()
    assert tuple(path.read_bytes() for path in outputs) == before


def test_confirmation_generation_stage_infrastructure_abort_publishes_nothing(tmp_path: Path) -> None:
    config, store = _stage_store(tmp_path, task_count=20)
    run_prompt_variant_freeze_stage(config, store, force=False)
    run_confirmation_randomization_stage(config, store, force=False)

    class FailingProvider:
        def generate_many(self, _requests):
            raise RuntimeError("authorization secret")

    with pytest.raises(SecAwareError) as caught:
        run_confirmation_generation_stage(config, store, force=False, provider=FailingProvider())
    assert "authorization secret" not in str(caught.value)
    assert all(
        not store.path("generation", name).exists()
        for name, _model in CONFIRMATION_GENERATION_OUTPUTS
    )


def test_assignment_manifest_replacement_during_provider_call_aborts_commit(tmp_path: Path) -> None:
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

    with pytest.raises(SecAwareError):
        run_confirmation_generation_stage(
            config, store, force=False, provider=ReplacingProvider()
        )
    assert all(
        not store.path("generation", name).exists()
        for name, _model in CONFIRMATION_GENERATION_OUTPUTS
    )

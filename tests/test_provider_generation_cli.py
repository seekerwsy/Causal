from pathlib import Path

import pytest
from typer.testing import CliRunner

from secaware import cli as cli_module
from secaware.cli import (
    app,
    extract_code_tsg_stage,
    generate_observed_stage,
    generate_provider_stage,
    import_generation_stage,
    plan_generation_stage,
    run_oracle_stage,
)
from secaware.config import AppConfig, load_config, write_resolved_config
from secaware.errors import ErrorCode, SecAwareError
from secaware.generation.openai_compatible_provider import (
    OpenAICompatibleGenerationResult,
)
from secaware.generation.mock_provider import MockProvider
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.io.run_store import RunStore
from secaware.pipeline.manifest import read_stage_manifest
from secaware.pipeline.artifact import canonical_sha256, sha256_path
from secaware.pipeline.manifest import (
    StageManifest,
    build_stage_fingerprint,
    write_stage_manifest,
)
from secaware.schema.common import SCHEMA_VERSION
from secaware.schema.generation import (
    GenerationAttemptRecord,
    GenerationProvenance,
    GenerationRequestRecord,
    OfflineGenerationResultRecord,
    sha256_text,
)
from secaware.schema.hypotheses import FactorType
from secaware.schema.interventions import InterventionRecord
from secaware.schema.records import CanonicalGeneratedCodeRecord, PromptRecord


_BASE_URL = "https://provider.private.invalid/v1"
_SYSTEM_TEMPLATE = "Return only Python source code."


def _prompt(prompt_id: str, split: str = "confirm") -> PromptRecord:
    return PromptRecord(
        prompt_id=prompt_id,
        split=split,  # type: ignore[arg-type]
        language="python",
        task_family="path_handling",
        cwe="CWE-22",
        prompt=f"Open the path for {prompt_id}.",
    )


def _config(tmp_path: Path, prompts_path: Path) -> AppConfig:
    return AppConfig.model_validate(
        {
            "run": {"name": "provider", "output_dir": str(tmp_path / "run")},
            "data": {"prompts_path": str(prompts_path)},
            "generation": {
                "provider": "openai_compatible",
                "models": ["model-b", "model-a"],
                "seeds": [2, 1],
                "openai_compatible": {
                    "base_url": _BASE_URL,
                    "api_key_env": "SECAWARE_TEST_API_KEY",
                    "system_template": _SYSTEM_TEMPLATE,
                    "system_template_version": "python-secure-v1",
                    "parameters": {"values": {"temperature": 0.1, "max_tokens": 128}},
                },
            },
        }
    )


def _prepared_store(
    tmp_path: Path,
) -> tuple[AppConfig, RunStore, list[PromptRecord]]:
    prompts = [_prompt("prompt-b"), _prompt("prompt-a", "discover")]
    prompts_path = tmp_path / "source-prompts.jsonl"
    write_jsonl(prompts_path, prompts)
    config = _config(tmp_path, prompts_path)
    store = RunStore(config)
    store.prepare()
    return config, store, prompts


def _intervention(prompt: PromptRecord) -> InterventionRecord:
    return InterventionRecord(
        intervention_id="intervention-a",
        prompt_id=prompt.prompt_id,
        hypothesis_id="hypothesis-a",
        factor_type=FactorType.PATH_NORMALIZATION,
        operator="add_path_normalization_requirement",
        expected_direction="risk_down_when_added",
        original_prompt=prompt.prompt,
        counterfactual_prompt="Normalize the path before opening it.",
        patch_success=True,
        round_trip_valid=True,
        semantic_valid=True,
        target_changed=True,
        side_effect=False,
    )


def _offline_result(request: GenerationRequestRecord) -> OfflineGenerationResultRecord:
    code = f"def offline_{request.seed_id}():\n    return {request.seed_id}\n"
    payload = request.model_dump(mode="python", round_trip=True, warnings=False)
    payload.update(
        code=code,
        code_sha256=sha256_text(code),
        provenance=GenerationProvenance(
            producer="offline-worker",
            producer_version="1.0",
        ),
    )
    return OfflineGenerationResultRecord.model_validate(payload)


class FakeProvider:
    def __init__(self) -> None:
        self.calls: list[tuple[GenerationRequestRecord, str]] = []

    def generate(
        self,
        request: GenerationRequestRecord,
        system_template: str,
    ) -> OpenAICompatibleGenerationResult:
        self.calls.append((request, system_template))
        code = f"def generated_{len(self.calls)}():\n    return {request.seed_id}\n"
        return OpenAICompatibleGenerationResult(
            code=code,
            provenance=GenerationProvenance(
                producer="openai_compatible",
                producer_version="chat_completions-v1",
            ),
            attempts=(
                GenerationAttemptRecord(
                    schema_version=SCHEMA_VERSION,
                    request_id=request.request_id,
                    attempt=1,
                    outcome="success",
                    error_code=None,
                    retryable=False,
                    backoff_seconds=0.0,
                ),
            ),
        )


def test_provider_plan_uses_fixed_path_config_identity_and_committed_manifest(
    tmp_path: Path,
) -> None:
    config, store, _ = _prepared_store(tmp_path)

    plan_generation_stage(
        config,
        store,
        condition="observed",
        mode="provider",
        force=False,
    )

    ledger = store.path("generation", "observed_requests.jsonl")
    records = read_jsonl(ledger, GenerationRequestRecord, required=True, allow_empty=False)
    manifest = read_stage_manifest(store.path(".stages", "plan-provider-generation-observed.json"))
    assert [record.prompt_id for record in records] == [
        prompt_id for prompt_id in ("prompt-a", "prompt-b") for _ in range(4)
    ]
    assert all(record.endpoint_type == "chat_completions" for record in records)
    assert all(record.endpoint_sha256 == sha256_text(_BASE_URL) for record in records)
    assert all(record.system_template_sha256 == sha256_text(_SYSTEM_TEMPLATE) for record in records)
    assert all(record.system_template_version == "python-secure-v1" for record in records)
    assert all(
        record.parameters.values == {"temperature": 0.1, "max_tokens": 128} for record in records
    )
    assert _BASE_URL not in ledger.read_text(encoding="utf-8")
    assert manifest.stage == "plan-provider-generation-observed"
    assert manifest.outputs == ["generation/observed_requests.jsonl"]


def test_provider_generate_publishes_canonical_code_and_flat_attempts_in_ledger_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    plan_generation_stage(
        config,
        store,
        condition="observed",
        mode="provider",
        force=False,
    )
    ledger = read_jsonl(
        store.path("generation", "observed_requests.jsonl"),
        GenerationRequestRecord,
        required=True,
        allow_empty=False,
    )
    provider = FakeProvider()
    monkeypatch.setattr(
        cli_module,
        "create_openai_compatible_provider",
        lambda provider_config: provider,
    )

    generate_provider_stage(config, store, condition="observed", force=False)

    code = read_jsonl(
        store.path("generation", "observed_code.jsonl"),
        CanonicalGeneratedCodeRecord,
        required=True,
        allow_empty=False,
    )
    attempts = read_jsonl(
        store.path("generation", "observed_attempts.jsonl"),
        GenerationAttemptRecord,
        required=True,
        allow_empty=False,
    )
    manifest = read_stage_manifest(store.path(".stages", "generate-provider-observed.json"))
    assert [request.request_id for request, _ in provider.calls] == [
        request.request_id for request in ledger
    ]
    assert all(template == _SYSTEM_TEMPLATE for _, template in provider.calls)
    assert [record.request_id for record in code] == [request.request_id for request in ledger]
    assert [attempt.request_id for attempt in attempts] == [
        request.request_id for request in ledger
    ]
    assert manifest.outputs == [
        "generation/observed_code.jsonl",
        "generation/observed_attempts.jsonl",
    ]


def test_provider_plan_and_generate_support_counterfactual_condition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, prompts = _prepared_store(tmp_path)
    intervention = _intervention(prompts[0])
    write_jsonl(store.path("interventions", "interventions.jsonl"), [intervention])
    provider = FakeProvider()
    monkeypatch.setattr(
        cli_module,
        "create_openai_compatible_provider",
        lambda provider_config: provider,
    )

    plan_generation_stage(
        config,
        store,
        condition="counterfactual",
        mode="provider",
        force=False,
    )
    generate_provider_stage(config, store, condition="counterfactual", force=False)

    records = read_jsonl(
        store.path("generation", "counterfactual_code.jsonl"),
        CanonicalGeneratedCodeRecord,
        required=True,
        allow_empty=False,
    )
    assert all(record.hypothesis_id == intervention.hypothesis_id for record in records)
    assert all(record.intervention_id == intervention.intervention_id for record in records)
    assert all(record.condition == "counterfactual" for record in records)


def test_plan_generation_mode_errors_are_safe_and_help_is_internal(
    tmp_path: Path,
) -> None:
    config, _, _ = _prepared_store(tmp_path)
    config_path = tmp_path / "config.yaml"
    write_resolved_config(config, config_path)
    secret = "private-invalid-provider-mode"

    invalid = CliRunner().invoke(
        app,
        [
            "plan-generation",
            "--config",
            str(config_path),
            "--mode",
            secret,
        ],
    )
    help_result = CliRunner().invoke(app, ["plan-generation", "--help"])

    assert invalid.exit_code == int(ErrorCode.CONFIG)
    assert secret not in invalid.output + invalid.stderr
    assert "Traceback" not in invalid.output + invalid.stderr
    assert help_result.exit_code == 0
    assert "--mode" not in help_result.output


def test_provider_generation_stage_requires_an_output_seal(tmp_path: Path) -> None:
    config, store, _ = _prepared_store(tmp_path)
    stage = "generate-provider-observed"
    ledger = store.path("generation", "observed_requests.jsonl")
    output = store.path("generation", "observed_code.jsonl")
    attempts = store.path("generation", "observed_attempts.jsonl")
    ledger.write_text("{}\n", encoding="utf-8")
    output.write_text("{}\n", encoding="utf-8")
    attempts.write_text("{}\n", encoding="utf-8")
    store.should_skip_stage(stage, [ledger], [output, attempts], False)

    with pytest.raises(SecAwareError) as exc_info:
        store.record_stage(stage, [ledger], [output, attempts])

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert not store.path(".stages", f"{stage}.json").exists()


def test_provider_plan_modes_share_ledger_and_invalidate_the_alternate_manifest(
    tmp_path: Path,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    provider_manifest = store.path(".stages", "plan-provider-generation-observed.json")
    offline_manifest = store.path(".stages", "plan-generation-observed.json")
    ledger = store.path("generation", "observed_requests.jsonl")

    plan_generation_stage(
        config,
        store,
        condition="observed",
        mode="provider",
        force=False,
    )
    assert provider_manifest.exists()
    plan_generation_stage(
        config,
        store,
        condition="observed",
        mode="offline",
        force=False,
    )
    assert offline_manifest.exists()
    assert not provider_manifest.exists()
    offline = read_jsonl(ledger, GenerationRequestRecord, required=True, allow_empty=False)
    assert all(record.endpoint_type == "offline" for record in offline)

    plan_generation_stage(
        config,
        store,
        condition="observed",
        mode="provider",
        force=False,
    )
    assert provider_manifest.exists()
    assert not offline_manifest.exists()
    provider = read_jsonl(ledger, GenerationRequestRecord, required=True, allow_empty=False)
    assert all(record.endpoint_type == "chat_completions" for record in provider)


def test_provider_generate_skip_and_force_control_factory_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    plan_generation_stage(
        config,
        store,
        condition="observed",
        mode="provider",
        force=False,
    )
    providers: list[FakeProvider] = []

    def factory(provider_config: object) -> FakeProvider:
        del provider_config
        provider = FakeProvider()
        providers.append(provider)
        return provider

    monkeypatch.setattr(cli_module, "create_openai_compatible_provider", factory)
    generate_provider_stage(config, store, condition="observed", force=False)
    assert len(providers) == 1

    generate_provider_stage(config, store, condition="observed", force=False)
    assert len(providers) == 1

    generate_provider_stage(config, store, condition="observed", force=True)
    assert len(providers) == 2
    assert providers[1].calls


@pytest.mark.parametrize(
    ("failure", "expected_code"),
    [("typed", ErrorCode.API_AUTH), ("raw", ErrorCode.CONTRACT)],
)
def test_provider_failure_preserves_old_bytes_but_removes_producer_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    expected_code: ErrorCode,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    plan_generation_stage(
        config,
        store,
        condition="observed",
        mode="provider",
        force=False,
    )
    monkeypatch.setattr(
        cli_module,
        "create_openai_compatible_provider",
        lambda provider_config: FakeProvider(),
    )
    generate_provider_stage(config, store, condition="observed", force=False)
    code_output = store.path("generation", "observed_code.jsonl")
    attempts_output = store.path("generation", "observed_attempts.jsonl")
    before = (code_output.read_bytes(), attempts_output.read_bytes())

    class FailingProvider:
        def generate(self, request: object, system_template: object) -> object:
            del request, system_template
            if failure == "typed":
                raise SecAwareError(
                    code=ErrorCode.API_AUTH,
                    stage="generation",
                    message="provider request failed",
                )
            raise RuntimeError("private-provider-exception-body")

    monkeypatch.setattr(
        cli_module,
        "create_openai_compatible_provider",
        lambda provider_config: FailingProvider(),
    )
    with pytest.raises(SecAwareError) as exc_info:
        generate_provider_stage(config, store, condition="observed", force=True)

    assert exc_info.value.code is expected_code
    assert "private-provider-exception-body" not in str(exc_info.value)
    assert (code_output.read_bytes(), attempts_output.read_bytes()) == before
    assert not store.path(".stages", "generate-provider-observed.json").exists()


def test_provider_generation_rejects_tampered_plan_without_calling_factory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    plan_generation_stage(
        config,
        store,
        condition="observed",
        mode="provider",
        force=False,
    )
    ledger = store.path("generation", "observed_requests.jsonl")
    ledger.write_bytes(ledger.read_bytes() + b"\n")
    calls = 0

    def factory(provider_config: object) -> FakeProvider:
        nonlocal calls
        del provider_config
        calls += 1
        return FakeProvider()

    monkeypatch.setattr(cli_module, "create_openai_compatible_provider", factory)
    with pytest.raises(SecAwareError) as exc_info:
        generate_provider_stage(config, store, condition="observed", force=False)

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert calls == 0
    assert not store.path(".stages", "generate-provider-observed.json").exists()


def test_provider_output_is_accepted_by_both_committed_downstream_gates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    plan_generation_stage(
        config,
        store,
        condition="observed",
        mode="provider",
        force=False,
    )
    monkeypatch.setattr(
        cli_module,
        "create_openai_compatible_provider",
        lambda provider_config: FakeProvider(),
    )
    generate_provider_stage(config, store, condition="observed", force=False)

    extract_code_tsg_stage(config, store, condition="observed", force=False)
    run_oracle_stage(config, store, condition="observed", force=False)

    assert store.path(".stages", "extract-code-tsg-observed.json").exists()
    assert store.path(".stages", "run-oracle-observed.json").exists()


def test_failed_provider_rerun_makes_old_code_unavailable_to_downstream(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    plan_generation_stage(
        config,
        store,
        condition="observed",
        mode="provider",
        force=False,
    )
    monkeypatch.setattr(
        cli_module,
        "create_openai_compatible_provider",
        lambda provider_config: FakeProvider(),
    )
    generate_provider_stage(config, store, condition="observed", force=False)
    extract_code_tsg_stage(config, store, condition="observed", force=False)

    class FailingProvider:
        def generate(self, request: object, system_template: object) -> object:
            del request, system_template
            raise SecAwareError(
                code=ErrorCode.API_TIMEOUT,
                stage="generation",
                message="provider request failed",
            )

    monkeypatch.setattr(
        cli_module,
        "create_openai_compatible_provider",
        lambda provider_config: FailingProvider(),
    )
    with pytest.raises(SecAwareError):
        generate_provider_stage(config, store, condition="observed", force=True)

    with pytest.raises(SecAwareError) as exc_info:
        extract_code_tsg_stage(config, store, condition="observed", force=False)

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert not store.path(".stages", "extract-code-tsg-observed.json").exists()


def test_compatibility_observed_entrypoint_dispatches_to_provider_pipeline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    provider = FakeProvider()
    monkeypatch.setattr(
        cli_module,
        "create_openai_compatible_provider",
        lambda provider_config: provider,
    )

    generate_observed_stage(config, store, force=False)

    assert provider.calls
    assert store.path(".stages", "plan-provider-generation-observed.json").exists()
    assert store.path(".stages", "generate-provider-observed.json").exists()


def test_generate_cli_prepares_plans_and_generates_without_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _, _ = _prepared_store(tmp_path)
    config_path = tmp_path / "config.yaml"
    write_resolved_config(config, config_path)
    provider = FakeProvider()
    monkeypatch.setenv("SECAWARE_TEST_API_KEY", "private-test-key")
    monkeypatch.setattr(
        cli_module,
        "create_openai_compatible_provider",
        lambda provider_config: provider,
    )

    result = CliRunner().invoke(
        app,
        ["generate", "--config", str(config_path), "--condition", "observed"],
    )

    assert result.exit_code == 0, result.output + result.stderr
    assert provider.calls
    assert _BASE_URL not in result.output + result.stderr
    assert _SYSTEM_TEMPLATE not in result.output + result.stderr


def test_offline_and_provider_producers_invalidate_each_other(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    monkeypatch.setattr(
        cli_module,
        "create_openai_compatible_provider",
        lambda provider_config: FakeProvider(),
    )
    plan_generation_stage(
        config,
        store,
        condition="observed",
        mode="provider",
        force=False,
    )
    generate_provider_stage(config, store, condition="observed", force=False)
    provider_manifest = store.path(".stages", "generate-provider-observed.json")
    import_manifest = store.path(".stages", "import-generation-observed.json")
    assert provider_manifest.exists()

    plan_generation_stage(
        config,
        store,
        condition="observed",
        mode="offline",
        force=False,
    )
    offline_requests = read_jsonl(
        store.path("generation", "observed_requests.jsonl"),
        GenerationRequestRecord,
        required=True,
        allow_empty=False,
    )
    results = tmp_path / "offline-results.jsonl"
    write_jsonl(results, [_offline_result(request) for request in offline_requests])
    import_generation_stage(
        config,
        store,
        condition="observed",
        results_path=results,
        force=False,
    )
    assert import_manifest.exists()
    assert not provider_manifest.exists()

    plan_generation_stage(
        config,
        store,
        condition="observed",
        mode="provider",
        force=False,
    )
    generate_provider_stage(config, store, condition="observed", force=False)
    assert provider_manifest.exists()
    assert not import_manifest.exists()


def test_tampered_provider_attempt_journal_revokes_downstream_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    plan_generation_stage(
        config,
        store,
        condition="observed",
        mode="provider",
        force=False,
    )
    monkeypatch.setattr(
        cli_module,
        "create_openai_compatible_provider",
        lambda provider_config: FakeProvider(),
    )
    generate_provider_stage(config, store, condition="observed", force=False)
    attempts = store.path("generation", "observed_attempts.jsonl")
    attempts.write_bytes(attempts.read_bytes() + b"\n")

    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_stage(config, store, condition="observed", force=False)

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert not store.path(".stages", "run-oracle-observed.json").exists()


def test_counterfactual_compatibility_entrypoint_dispatches_to_provider_pipeline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, prompts = _prepared_store(tmp_path)
    write_jsonl(
        store.path("interventions", "interventions.jsonl"),
        [_intervention(prompts[0])],
    )
    provider = FakeProvider()
    monkeypatch.setattr(
        cli_module,
        "create_openai_compatible_provider",
        lambda provider_config: provider,
    )

    cli_module.generate_counterfactual_stage(config, store, force=False)

    assert provider.calls
    assert store.path(".stages", "plan-provider-generation-counterfactual.json").exists()
    assert store.path(".stages", "generate-provider-counterfactual.json").exists()


def test_offline_import_rejects_provider_journal_alias_before_manifest_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    plan_generation_stage(
        config,
        store,
        condition="observed",
        mode="provider",
        force=False,
    )
    monkeypatch.setattr(
        cli_module,
        "create_openai_compatible_provider",
        lambda provider_config: FakeProvider(),
    )
    generate_provider_stage(config, store, condition="observed", force=False)
    journal = store.path("generation", "observed_attempts.jsonl")
    provider_manifest = store.path(".stages", "generate-provider-observed.json")
    before = provider_manifest.read_bytes()

    with pytest.raises(SecAwareError) as exc_info:
        import_generation_stage(
            config,
            store,
            condition="observed",
            results_path=journal,
            force=False,
        )

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert provider_manifest.read_bytes() == before


def test_producer_invalidation_attempts_every_alternate_after_one_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    called: list[str] = []
    real_invalidate = store.invalidate_stage

    def invalidate(stage: str) -> None:
        called.append(stage)
        if stage == "import-generation-observed":
            raise SecAwareError(
                code=ErrorCode.MANIFEST_CONFLICT,
                stage=stage,
                message="private invalidation failure",
            )
        real_invalidate(stage)

    monkeypatch.setattr(store, "invalidate_stage", invalidate)

    with pytest.raises(SecAwareError):
        generate_provider_stage(config, store, condition="observed", force=False)

    assert called == [
        "import-generation-observed",
        "generate-observed",
        "generate-provider-observed",
    ]


def test_provider_generate_rejects_output_changed_after_seal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    plan_generation_stage(
        config,
        store,
        condition="observed",
        mode="provider",
        force=False,
    )
    monkeypatch.setattr(
        cli_module,
        "create_openai_compatible_provider",
        lambda provider_config: FakeProvider(),
    )
    real_seal = store.seal_stage_outputs
    attempts_path = store.path("generation", "observed_attempts.jsonl")

    def seal_then_tamper(stage: str, outputs: list[Path]) -> None:
        real_seal(stage, outputs)
        attempts = read_jsonl(
            attempts_path,
            GenerationAttemptRecord,
            required=True,
            allow_empty=False,
        )
        write_jsonl(attempts_path, list(reversed(attempts)))

    monkeypatch.setattr(store, "seal_stage_outputs", seal_then_tamper)

    with pytest.raises(SecAwareError) as exc_info:
        generate_provider_stage(config, store, condition="observed", force=False)

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert not store.path(".stages", "generate-provider-observed.json").exists()


def test_provider_generate_rejects_attempts_bound_to_another_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    plan_generation_stage(
        config,
        store,
        condition="observed",
        mode="provider",
        force=False,
    )

    class WrongAttemptProvider(FakeProvider):
        def generate(
            self,
            request: GenerationRequestRecord,
            system_template: str,
        ) -> OpenAICompatibleGenerationResult:
            result = super().generate(request, system_template)
            return OpenAICompatibleGenerationResult(
                code=result.code,
                provenance=result.provenance,
                attempts=(result.attempts[0].model_copy(update={"request_id": f"req_{'0' * 64}"}),),
            )

    monkeypatch.setattr(
        cli_module,
        "create_openai_compatible_provider",
        lambda provider_config: WrongAttemptProvider(),
    )

    with pytest.raises(SecAwareError) as exc_info:
        generate_provider_stage(config, store, condition="observed", force=False)

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert not store.path(".stages", "generate-provider-observed.json").exists()


def test_generate_cli_preserves_provider_api_exit_code_and_redacts_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _, _ = _prepared_store(tmp_path)
    config_path = tmp_path / "config.yaml"
    write_resolved_config(config, config_path)
    monkeypatch.setenv("SECAWARE_TEST_API_KEY", "private-test-key")

    class FailingProvider:
        def generate(self, request: object, system_template: object) -> object:
            del request, system_template
            raise SecAwareError(
                code=ErrorCode.API_RATE_LIMIT,
                stage="generation",
                message="provider request failed",
                details={"raw_body": "private-response-body"},
                retryable=True,
            )

    monkeypatch.setattr(
        cli_module,
        "create_openai_compatible_provider",
        lambda provider_config: FailingProvider(),
    )

    result = CliRunner().invoke(
        app,
        ["generate", "--config", str(config_path), "--condition", "observed"],
    )

    assert result.exit_code == int(ErrorCode.API_RATE_LIMIT)
    surface = result.output + result.stderr
    assert "private-response-body" not in surface
    assert _BASE_URL not in surface
    assert _SYSTEM_TEMPLATE not in surface
    assert "Traceback" not in surface


def test_generate_cli_help_and_invalid_condition_use_only_safe_fixed_controls(
    tmp_path: Path,
) -> None:
    config, _, _ = _prepared_store(tmp_path)
    config_path = tmp_path / "config.yaml"
    write_resolved_config(config, config_path)
    secret = "private-invalid-condition"

    help_result = CliRunner().invoke(app, ["generate", "--help"])
    invalid = CliRunner().invoke(
        app,
        ["generate", "--config", str(config_path), "--condition", secret],
    )

    assert help_result.exit_code == 0
    assert "--condition" in help_result.output
    assert "--force" in help_result.output
    assert "--ledger" not in help_result.output
    assert "--output" not in help_result.output
    assert invalid.exit_code == int(ErrorCode.CONFIG)
    assert secret not in invalid.output + invalid.stderr


def test_legacy_api_stub_has_no_provider_fallback_and_cleans_failed_execution(
    tmp_path: Path,
) -> None:
    provider_config, _, prompts = _prepared_store(tmp_path)
    payload = provider_config.model_dump(mode="python")
    payload["generation"]["provider"] = "api"  # type: ignore[index]
    config = AppConfig.model_validate(payload)
    store = RunStore(config)
    store.prepare()

    with pytest.raises(SecAwareError) as first:
        generate_observed_stage(config, store, force=False)

    assert first.value.code is ErrorCode.CONFIG
    assert not store.stage_is_active("generate-observed")
    assert not store.path(".stages", "generate-observed.json").exists()
    retained: list[str] = []
    current = first.value.__traceback__
    while current is not None:
        if "/src/secaware/" in current.tb_frame.f_code.co_filename.replace("\\", "/"):
            retained.append(repr(current.tb_frame.f_locals))
        current = current.tb_next
    assert all(prompt.prompt not in "\n".join(retained) for prompt in prompts)

    with pytest.raises(SecAwareError) as second:
        generate_observed_stage(config, store, force=False)

    assert second.value.code is ErrorCode.CONFIG


def test_run_all_dispatches_both_conditions_through_provider_without_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    demo = load_config("configs/demo.yaml", run_dir=tmp_path / "run")
    payload = demo.model_dump(mode="python")
    payload["generation"] = {
        "provider": "openai_compatible",
        "models": ["model-provider"],
        "seeds": [1, 2],
        "openai_compatible": {
            "base_url": _BASE_URL,
            "api_key_env": "SECAWARE_TEST_API_KEY",
            "system_template": _SYSTEM_TEMPLATE,
            "system_template_version": "python-secure-v1",
            "parameters": {"values": {"temperature": 0.1}},
        },
    }
    config = AppConfig.model_validate(payload)
    config_path = tmp_path / "provider-demo.yaml"
    write_resolved_config(config, config_path)
    monkeypatch.setenv("SECAWARE_TEST_API_KEY", "private-test-key")
    providers: list[object] = []

    class MockBackedProvider:
        def __init__(self) -> None:
            self.mock = MockProvider()

        def generate(
            self,
            request: GenerationRequestRecord,
            system_template: str,
        ) -> OpenAICompatibleGenerationResult:
            del system_template
            code = self.mock.generate(
                request.prompt,
                model_id=request.model_id,
                seed=request.seed_id,
                language=request.language,
            )
            return OpenAICompatibleGenerationResult(
                code=code,
                provenance=GenerationProvenance(
                    producer="openai_compatible",
                    producer_version="chat_completions-v1",
                ),
                attempts=(
                    GenerationAttemptRecord(
                        schema_version=SCHEMA_VERSION,
                        request_id=request.request_id,
                        attempt=1,
                        outcome="success",
                        error_code=None,
                        retryable=False,
                        backoff_seconds=0.0,
                    ),
                ),
            )

    def factory(provider_config: object) -> MockBackedProvider:
        del provider_config
        provider = MockBackedProvider()
        providers.append(provider)
        return provider

    monkeypatch.setattr(cli_module, "create_openai_compatible_provider", factory)

    result = CliRunner().invoke(app, ["run-all", "--config", str(config_path), "--force"])

    assert result.exit_code == 0, result.output + result.stderr
    assert len(providers) == 2
    run_dir = tmp_path / "run"
    for condition in ("observed", "counterfactual"):
        assert (run_dir / ".stages" / f"plan-provider-generation-{condition}.json").exists()
        assert (run_dir / ".stages" / f"generate-provider-{condition}.json").exists()
        assert not (run_dir / ".stages" / f"generate-{condition}.json").exists()
    assert (run_dir / "reports" / "summary.md").exists()


def test_missing_offline_results_attempts_to_revoke_every_generation_producer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    called: list[str] = []
    real_invalidate = store.invalidate_stage

    def invalidate(stage: str) -> None:
        called.append(stage)
        if stage == "generate-observed":
            raise SecAwareError(
                code=ErrorCode.MANIFEST_CONFLICT,
                stage=stage,
                message="private legacy invalidation failure",
            )
        real_invalidate(stage)

    monkeypatch.setattr(store, "invalidate_stage", invalidate)

    with pytest.raises(SecAwareError):
        import_generation_stage(
            config,
            store,
            condition="observed",
            results_path=tmp_path / "missing-results.jsonl",
            force=False,
        )

    assert called == [
        "import-generation-observed",
        "generate-observed",
        "generate-provider-observed",
    ]


def test_old_code_manifest_and_v10_ledger_are_rerun_instead_of_skipped(
    tmp_path: Path,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    stage = "plan-provider-generation-observed"
    inputs = [store.path("inputs", "prompts.jsonl")]
    ledger = store.path("generation", "observed_requests.jsonl")
    current = cli_module.plan_observed_requests(
        read_jsonl(inputs[0], PromptRecord, required=True, allow_empty=False),
        config.generation.models,
        config.generation.seeds,
        endpoint_type="chat_completions",
        endpoint_identity=_BASE_URL,
        parameters=config.generation.openai_compatible.parameters,  # type: ignore[union-attr]
        system_template=_SYSTEM_TEMPLATE,
        system_template_version="python-secure-v1",
    )
    legacy: list[dict[str, object]] = []
    for request in current:
        payload = request.model_dump(mode="json")
        payload["schema_version"] = "1.0"
        payload.pop("endpoint_sha256")
        identity = {
            key: payload[key]
            for key in (
                "schema_version",
                "condition",
                "prompt_id",
                "prompt_sha256",
                "language",
                "model_id",
                "seed_id",
                "hypothesis_id",
                "intervention_id",
                "endpoint_type",
                "system_template_version",
                "system_template_sha256",
                "parameters",
            )
        }
        payload["request_id"] = f"req_{canonical_sha256(identity)}"
        legacy.append(payload)
    write_jsonl(ledger, legacy)
    stage_inputs = store.stage_inputs(inputs)
    config_payload = config.model_dump(mode="json")
    relative_output = "generation/observed_requests.jsonl"
    write_stage_manifest(
        store.path(".stages", f"{stage}.json"),
        StageManifest(
            schema_version=SCHEMA_VERSION,
            stage=stage,
            fingerprint=build_stage_fingerprint(
                stage,
                stage_inputs,
                config_payload,
                policy_sha256=None,
                catalog_sha256=None,
                code_version="0.1.0",
            ),
            inputs=stage_inputs,
            config_sha256=canonical_sha256(config_payload),
            code_version="0.1.0",
            outputs=[relative_output],
            output_sha256={relative_output: sha256_path(ledger)},
        ),
    )

    plan_generation_stage(
        config,
        store,
        condition="observed",
        mode="provider",
        force=False,
    )

    migrated = read_jsonl(
        ledger,
        GenerationRequestRecord,
        required=True,
        allow_empty=False,
    )
    assert all(request.schema_version == "1.1" for request in migrated)
    manifest = read_stage_manifest(store.path(".stages", f"{stage}.json"))
    assert manifest.code_version == "0.2.0"

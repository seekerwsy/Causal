from pathlib import Path

import pytest
from typer.testing import CliRunner

from secaware import cli as cli_module
from secaware.cli import app, generate_observed_stage
from secaware.config import AppConfig, write_resolved_config
from secaware.errors import ErrorCode, SecAwareError
from secaware.generation.openai_compatible_provider import (
    OpenAICompatibleGenerationResult,
)
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.io.run_store import RunStore
from secaware.pipeline.manifest import read_stage_manifest
from secaware.schema.common import SCHEMA_VERSION
from secaware.schema.generation import (
    GenerationAttemptRecord,
    GenerationProvenance,
    GenerationRequestRecord,
    ProviderUsageRecord,
    sha256_text,
)
from secaware.schema.records import CanonicalGeneratedCodeRecord, PromptRecord


_BASE_URL = "https://provider.private.invalid/v1"
_SYSTEM_TEMPLATE = "Return only Python source code."


def _prompt(prompt_id: str) -> PromptRecord:
    return PromptRecord(
        prompt_id=prompt_id,
        task_id=f"task-{prompt_id}",
        split="discover",
        language="python",
        task_family="path_handling",
        cwe="CWE-22",
        prompt=f"Open the path for {prompt_id}.",
        prompt_role="neutral_baseline",
        counterpart_prompt_id=None,
    )


def _config(tmp_path: Path, prompts_path: Path) -> AppConfig:
    attestations_path = tmp_path / "attestations.jsonl"
    write_jsonl(attestations_path, [])
    return AppConfig.model_validate(
        {
            "run": {"name": "provider", "output_dir": str(tmp_path / "run")},
            "data": {
                "prompts_path": str(prompts_path),
                "prompt_attestations_path": str(attestations_path),
            },
            "tsg": {"prompt_extractor": "deterministic_catalog_v1"},
            "intervention": {"executor": "deterministic"},
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


def _prepared_store(tmp_path: Path) -> tuple[AppConfig, RunStore]:
    prompts_path = tmp_path / "source-prompts.jsonl"
    write_jsonl(prompts_path, [_prompt("prompt-b"), _prompt("prompt-a")])
    config = _config(tmp_path, prompts_path)
    store = RunStore(config)
    store.prepare()
    return config, store


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
            usage=ProviderUsageRecord(
                prompt_tokens=1,
                completion_tokens=1,
                total_tokens=2,
            ),
            runtime_fingerprint_sha256="c" * 64,
        )


def _plan(config: AppConfig, store: RunStore, *, force: bool = False) -> None:
    cli_module._plan_provider_observed_generation(config, store, force=force)


def _generate(config: AppConfig, store: RunStore, *, force: bool = False) -> None:
    cli_module._generate_provider_observed(config, store, force=force)


def test_observed_provider_plan_binds_fixed_inputs_and_committed_manifest(
    tmp_path: Path,
) -> None:
    config, store = _prepared_store(tmp_path)

    _plan(config, store)

    ledger = store.path("generation", "observed_requests.jsonl")
    records = read_jsonl(
        ledger,
        GenerationRequestRecord,
        required=True,
        allow_empty=False,
    )
    manifest = read_stage_manifest(store.path(".stages", "plan-provider-generation-observed.json"))
    assert [record.prompt_id for record in records] == [
        prompt_id for prompt_id in ("prompt-a", "prompt-b") for _ in range(4)
    ]
    assert all(record.condition == "observed" for record in records)
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


def test_observed_provider_publishes_code_and_attempts_in_ledger_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _prepared_store(tmp_path)
    _plan(config, store)
    requests = read_jsonl(
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

    _generate(config, store)

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
        request.request_id for request in requests
    ]
    assert all(template == _SYSTEM_TEMPLATE for _, template in provider.calls)
    assert [record.request_id for record in code] == [request.request_id for request in requests]
    assert [attempt.request_id for attempt in attempts] == [
        request.request_id for request in requests
    ]
    assert manifest.outputs == [
        "generation/observed_code.jsonl",
        "generation/observed_attempts.jsonl",
    ]


def test_observed_provider_skip_and_force_control_factory_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _prepared_store(tmp_path)
    _plan(config, store)
    providers: list[FakeProvider] = []

    def factory(provider_config: object) -> FakeProvider:
        del provider_config
        provider = FakeProvider()
        providers.append(provider)
        return provider

    monkeypatch.setattr(cli_module, "create_openai_compatible_provider", factory)
    _generate(config, store)
    _generate(config, store)
    _generate(config, store, force=True)

    assert len(providers) == 2
    assert providers[1].calls


@pytest.mark.parametrize(
    ("failure", "expected_code"),
    [("typed", ErrorCode.API_AUTH), ("raw", ErrorCode.CONTRACT)],
)
def test_observed_provider_failure_preserves_bytes_and_revokes_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    expected_code: ErrorCode,
) -> None:
    config, store = _prepared_store(tmp_path)
    _plan(config, store)
    monkeypatch.setattr(
        cli_module,
        "create_openai_compatible_provider",
        lambda provider_config: FakeProvider(),
    )
    _generate(config, store)
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
        _generate(config, store, force=True)

    assert exc_info.value.code is expected_code
    assert "private-provider-exception-body" not in str(exc_info.value)
    assert (code_output.read_bytes(), attempts_output.read_bytes()) == before
    assert not store.path(".stages", "generate-provider-observed.json").exists()


def test_observed_provider_rejects_tampered_plan_before_factory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _prepared_store(tmp_path)
    _plan(config, store)
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
        _generate(config, store)

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert calls == 0
    assert not store.path(".stages", "generate-provider-observed.json").exists()


def test_generate_observed_stage_is_the_provider_compatibility_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _prepared_store(tmp_path)
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
    assert not hasattr(cli_module, "generate_provider_stage")
    assert not hasattr(cli_module, "plan_generation_stage")


def test_generate_observed_cli_uses_only_the_final_command_surface(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _ = _prepared_store(tmp_path)
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
        ["generate-observed", "--config", str(config_path)],
    )

    assert result.exit_code == 0, result.output
    assert provider.calls
    help_result = CliRunner().invoke(app, ["--help"])
    assert help_result.exit_code == 0
    assert "generate-observed" in help_result.output
    for retired in ("plan-generation", "import-generation", "generate-counterfactual"):
        assert retired not in help_result.output

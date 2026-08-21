import json
from pathlib import Path
import threading
from dataclasses import replace

import pytest
from typer.testing import CliRunner

from secaware.cli import _prompt_records, app, extract_prompt_tsg_stage
from secaware.config import AppConfig, TSGConfig, load_config
from secaware.errors import ErrorCode, SecAwareError
from secaware.extractors.deterministic_catalog import DeterministicCatalogExtractor
from secaware.extractors import factory as extractor_factory_module
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.io.run_store import RunStore
from secaware.io import run_store as run_store_module
from secaware.pipeline import jsonl_stage as jsonl_stage_module
from secaware.pipeline.manifest import read_stage_manifest
from secaware.pipeline.stages.prompt_extraction import (
    read_source_prompts,
    run_prompt_extraction_stage,
    validate_exact_extraction_coverage,
)
from secaware.schema.features import PromptExtractorBackend
from secaware.schema.prompt_extraction import PromptExtractionProposalRecord
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import PromptTSGRecord
from secaware.tsg.catalog import PROMPT_TSG_CATALOG_SHA256
from secaware.tsg.contract import (
    PROMPT_TSG_EXTRACTOR_VERSION,
    TSG_SCHEMA_VERSION,
    build_prompt_tsg_stage_contract_sha256,
)
from secaware.extractors.factory import extraction_policy


_TEST_LLM_COORDINATES = {
    "provider": "openai_compatible",
    "model_id": "prompt-stage-test-model",
    "base_url": "https://prompt-stage.invalid/v1",
    "api_key_env": "SECAWARE_PROMPT_STAGE_TEST_KEY",
    "timeout_seconds": 30.0,
    "max_attempts": 1,
    "max_response_bytes": 262_144,
    "temperature": 0.0,
    "top_p": 1.0,
    "seed": 0,
}


def _prepared_store(tmp_path: Path) -> tuple[object, RunStore]:
    config = load_config("configs/demo.yaml", run_dir=tmp_path / "run")
    store = RunStore(config)
    store.prepare()
    return config, store


def _prompt_extraction_outputs(store: RunStore) -> list[Path]:
    return [
        store.path("tsg", "prompt_extraction_proposals.jsonl"),
        store.path("tsg", "prompt_tsg.jsonl"),
    ]


def _llm_config(
    config: AppConfig,
    backend: PromptExtractorBackend,
) -> AppConfig:
    payload = config.model_dump(mode="python", round_trip=True, warnings=False)
    payload["tsg"] = {
        "prompt_extractor": backend,
        "llm": dict(_TEST_LLM_COORDINATES),
    }
    return AppConfig.model_validate(payload)


class _DeterministicFactsTransport:
    def __init__(self, prompts: tuple[object, ...]) -> None:
        self.prompts = {prompt.prompt_id: prompt for prompt in prompts}  # type: ignore[attr-defined]
        self.calls = 0
        self.policy = extraction_policy(
            TSGConfig(prompt_extractor=PromptExtractorBackend.DETERMINISTIC_CATALOG_V1)
        )

    def complete(self, request_bytes: bytes, policy: object) -> bytes:
        del policy
        self.calls += 1
        request = json.loads(request_bytes)
        proposal = DeterministicCatalogExtractor().extract(
            self.prompts[request["prompt_id"]],  # type: ignore[arg-type]
            self.policy,
        )
        assert proposal.raw_response is not None
        response = json.loads(proposal.raw_response)
        response["facts"] = [
            fact for fact in response["facts"] if fact["state"] != "not_applicable"
        ]
        for fact in response["facts"]:
            for span in fact["evidence"]:
                span.pop("start")
                span.pop("end")
                span.pop("text_sha256")
        return json.dumps(
            response,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")


class _FailingTransport:
    def __init__(self) -> None:
        self.calls = 0

    def complete(self, request_bytes: bytes, policy: object) -> bytes:
        del request_bytes, policy
        self.calls += 1
        raise RuntimeError("selected transport failed")


def test_prompt_tsg_stage_records_catalog_bound_exact_v2_artifact(tmp_path: Path) -> None:
    config, store = _prepared_store(tmp_path)

    extract_prompt_tsg_stage(config, store, force=False)  # type: ignore[arg-type]

    output = store.path("tsg", "prompt_tsg.jsonl")
    records = read_jsonl(output, PromptTSGRecord, required=True, allow_empty=False)
    manifest = read_stage_manifest(store.path(".stages", "extract-prompt-tsg.json"))
    assert records
    assert all(type(record) is PromptTSGRecord for record in records)
    assert all(record.schema_version == "2.1" for record in records)
    assert manifest.catalog_sha256 == PROMPT_TSG_CATALOG_SHA256


def test_prompt_extraction_stage_commits_exact_proposal_and_graph_coverage(
    tmp_path: Path,
) -> None:
    config, store = _prepared_store(tmp_path)

    run_prompt_extraction_stage(config, store, force=False)  # type: ignore[arg-type]

    proposal_output = store.path("tsg", "prompt_extraction_proposals.jsonl")
    graph_output = store.path("tsg", "prompt_tsg.jsonl")
    proposals = read_jsonl(
        proposal_output,
        PromptExtractionProposalRecord,
        required=True,
        allow_empty=False,
    )
    graphs = read_jsonl(graph_output, PromptTSGRecord, required=True, allow_empty=False)
    manifest = read_stage_manifest(store.path(".stages", "extract-prompt-tsg.json"))
    assert [item.prompt_id for item in proposals] == [item.prompt_id for item in graphs]
    assert [item.proposal_id for item in proposals] == [item.proposal_id for item in graphs]
    assert manifest.outputs == [
        "tsg/prompt_extraction_proposals.jsonl",
        "tsg/prompt_tsg.jsonl",
    ]
    assert manifest.policy_sha256 == extraction_policy(config.tsg).policy_sha256  # type: ignore[union-attr]


@pytest.mark.parametrize("force", [False, True], ids=["resume", "force"])
def test_real_backend_drift_never_skips_or_mixes_extraction_records(
    tmp_path: Path,
    force: bool,
) -> None:
    original_config, original_store = _prepared_store(tmp_path)
    run_prompt_extraction_stage(original_config, original_store, force=False)  # type: ignore[arg-type]
    original_proposals = read_jsonl(
        original_store.path("tsg", "prompt_extraction_proposals.jsonl"),
        PromptExtractionProposalRecord,
        required=True,
        allow_empty=False,
    )

    facts_config = _llm_config(
        original_config,  # type: ignore[arg-type]
        PromptExtractorBackend.LLM_FACTS_V1,
    )
    facts_store = RunStore(facts_config)
    facts_store.prepare()
    prompts = tuple(_prompt_records(facts_store))
    transport = _DeterministicFactsTransport(prompts)
    run_prompt_extraction_stage(
        facts_config,
        facts_store,
        force=force,
        transport=transport,
    )

    proposals = read_jsonl(
        facts_store.path("tsg", "prompt_extraction_proposals.jsonl"),
        PromptExtractionProposalRecord,
        required=True,
        allow_empty=False,
    )
    graphs = read_jsonl(
        facts_store.path("tsg", "prompt_tsg.jsonl"),
        PromptTSGRecord,
        required=True,
        allow_empty=False,
    )
    current_policy = extraction_policy(facts_config.tsg)
    assert transport.calls == len(prompts)
    assert {item.backend for item in proposals} == {PromptExtractorBackend.LLM_FACTS_V1}
    assert {item.extractor_backend for item in graphs} == {PromptExtractorBackend.LLM_FACTS_V1}
    assert {item.policy_sha256 for item in proposals} == {current_policy.policy_sha256}
    assert {item.extractor_policy_sha256 for item in graphs} == {current_policy.policy_sha256}
    assert [item.proposal_id for item in proposals] == [item.proposal_id for item in graphs]
    assert {item.proposal_id for item in proposals}.isdisjoint(
        {item.proposal_id for item in original_proposals}
    )


def test_complete_llm_resume_skips_without_constructing_backend_or_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_config, original_store = _prepared_store(tmp_path)
    facts_config = _llm_config(
        original_config,  # type: ignore[arg-type]
        PromptExtractorBackend.LLM_FACTS_V1,
    )
    facts_store = RunStore(facts_config)
    facts_store.prepare()
    prompts = tuple(_prompt_records(facts_store))
    transport = _DeterministicFactsTransport(prompts)
    run_prompt_extraction_stage(
        facts_config,
        facts_store,
        force=False,
        transport=transport,
    )
    assert transport.calls == len(prompts)

    calls = {"transport": 0, "extractor": 0, "complete": 0}

    class UnexpectedTransport:
        def complete(self, request_bytes: bytes, policy: object) -> bytes:
            del request_bytes, policy
            calls["complete"] += 1
            raise AssertionError("skipped transport was called")

    def construct_transport(*args: object, **kwargs: object) -> UnexpectedTransport:
        del args, kwargs
        calls["transport"] += 1
        return UnexpectedTransport()

    def construct_extractor(*args: object, **kwargs: object) -> object:
        del args, kwargs
        calls["extractor"] += 1
        raise AssertionError("skipped extractor was constructed")

    monkeypatch.delenv(_TEST_LLM_COORDINATES["api_key_env"], raising=False)
    monkeypatch.setattr(
        extractor_factory_module,
        "OpenAICompatibleStructuredTransport",
        construct_transport,
    )
    monkeypatch.setattr(
        extractor_factory_module,
        "LLMFactsExtractor",
        construct_extractor,
    )

    run_prompt_extraction_stage(
        facts_config,
        RunStore(facts_config),
        force=False,
    )

    assert calls == {"transport": 0, "extractor": 0, "complete": 0}


@pytest.mark.parametrize("restore_original", [False, True], ids=["a-to-b", "a-to-b-to-a"])
def test_resume_revalidates_snapshot_before_returning_skip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    restore_original: bool,
) -> None:
    from secaware.pipeline.stages import prompt_extraction as stage_module

    config, store = _prepared_store(tmp_path)
    run_prompt_extraction_stage(config, store, force=False)  # type: ignore[arg-type]
    input_path = store.path("inputs", "prompts.jsonl")
    outputs = _prompt_extraction_outputs(store)
    manifest_path = store.path(".stages", "extract-prompt-tsg.json")
    protected = (*outputs, manifest_path)
    previous = tuple(path.read_bytes() for path in protected)
    original_input = input_path.read_bytes()
    changed_input = original_input.replace(
        b"opens a file path provided by the user",
        b"opens a named file provided by the user",
        1,
    )
    assert changed_input != original_input
    real_allows_skip = run_store_module.manifest_allows_skip
    backend_calls = 0
    skip_checks = 0

    def mutate_before_skip_check(*args: object, **kwargs: object) -> bool:
        nonlocal skip_checks
        skip_checks += 1
        input_path.write_bytes(changed_input)
        if restore_original:
            input_path.write_bytes(original_input)
        return real_allows_skip(*args, **kwargs)  # type: ignore[arg-type]

    def reject_backend_construction(*args: object, **kwargs: object) -> object:
        nonlocal backend_calls
        del args, kwargs
        backend_calls += 1
        raise AssertionError("resume failure constructed the backend")

    monkeypatch.setattr(run_store_module, "manifest_allows_skip", mutate_before_skip_check)
    monkeypatch.setattr(stage_module, "extractor_for_config", reject_backend_construction)
    resume_store = RunStore(config)  # type: ignore[arg-type]

    with pytest.raises(SecAwareError) as exc_info:
        run_prompt_extraction_stage(config, resume_store, force=False)  # type: ignore[arg-type]

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert skip_checks == 1
    assert backend_calls == 0
    assert tuple(path.read_bytes() for path in protected) == previous
    assert not store.path(".stages", ".extract-prompt-tsg.transaction.json").exists()
    assert not list(store.root.rglob("*.recovery.backup"))
    assert not list(store.path("tsg").glob(".*.stage.candidate"))
    assert not resume_store.stage_is_active("extract-prompt-tsg")


def test_prompt_snapshot_parser_preserves_json_string_line_separators(tmp_path: Path) -> None:
    _config, store = _prepared_store(tmp_path)
    source = tuple(_prompt_records(store))[0]
    special_prompt = "first\u2028second\u2029third"
    expected = source.model_copy(update={"prompt": special_prompt})
    input_path = store.path("inputs", "prompts.jsonl")
    write_jsonl(input_path, [expected], stage="extract-prompt-tsg")
    payload = input_path.read_bytes()
    assert "\u2028" in payload.decode("utf-8")
    assert "\u2029" in payload.decode("utf-8")

    regular = read_jsonl(
        input_path,
        PromptRecord,
        required=True,
        allow_empty=False,
        stage="extract-prompt-tsg",
    )
    snapshot = read_source_prompts(store, payload=payload)

    assert snapshot == tuple(regular)
    assert snapshot == (expected,)
    assert snapshot[0].prompt == special_prompt


def test_exact_coverage_rejects_omission_duplicate_extra_mixed_and_stale_records(
    tmp_path: Path,
) -> None:
    config, store = _prepared_store(tmp_path)
    run_prompt_extraction_stage(config, store, force=False)  # type: ignore[arg-type]
    prompts = tuple(_prompt_records(store))
    proposals = tuple(
        read_jsonl(
            store.path("tsg", "prompt_extraction_proposals.jsonl"),
            PromptExtractionProposalRecord,
            required=True,
            allow_empty=False,
        )
    )
    graphs = tuple(
        read_jsonl(
            store.path("tsg", "prompt_tsg.jsonl"),
            PromptTSGRecord,
            required=True,
            allow_empty=False,
        )
    )
    policy = extraction_policy(config.tsg)  # type: ignore[union-attr]

    invalid_cases = (
        (prompts, proposals[:-1], graphs[:-1]),
        (prompts, proposals[:-1] + proposals[:1], graphs),
        (prompts, proposals + proposals[:1], graphs + graphs[:1]),
        (
            prompts,
            proposals[:-1]
            + (proposals[-1].model_copy(update={"backend": PromptExtractorBackend.LLM_FACTS_V1}),),
            graphs,
        ),
        (
            prompts,
            proposals[:-1] + (proposals[-1].model_copy(update={"catalog_sha256": "0" * 64}),),
            graphs,
        ),
        (
            prompts,
            proposals[:-1] + (proposals[-1].model_copy(update={"policy_sha256": "f" * 64}),),
            graphs,
        ),
    )
    for source, candidates, records in invalid_cases:
        with pytest.raises(SecAwareError) as exc_info:
            validate_exact_extraction_coverage(source, candidates, records, policy)
        assert exc_info.value.code is ErrorCode.CONTRACT


def test_prompt_extraction_force_failure_restores_both_artifacts_and_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secaware.pipeline.stages import prompt_extraction as stage_module

    config, store = _prepared_store(tmp_path)
    run_prompt_extraction_stage(config, store, force=False)  # type: ignore[arg-type]
    paths = (
        store.path("tsg", "prompt_extraction_proposals.jsonl"),
        store.path("tsg", "prompt_tsg.jsonl"),
        store.path(".stages", "extract-prompt-tsg.json"),
    )
    previous = tuple(path.read_bytes() for path in paths)
    calls: list[str] = []

    class ExplodingExtractor:
        def extract(self, prompt: object, policy: object) -> object:
            del prompt, policy
            calls.append("selected-backend")
            raise RuntimeError("selected backend failed")

    monkeypatch.setattr(
        stage_module,
        "extractor_for_config",
        lambda *_args, **_kwargs: ExplodingExtractor(),
    )
    with pytest.raises(RuntimeError, match="selected backend failed"):
        run_prompt_extraction_stage(config, store, force=True)  # type: ignore[arg-type]

    assert calls == ["selected-backend"]
    assert tuple(path.read_bytes() for path in paths) == previous
    assert not store.stage_is_active("extract-prompt-tsg")


def test_prompt_input_aba_rewrite_fails_closed_and_restores_prior_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secaware.pipeline.stages import prompt_extraction as stage_module

    config, store = _prepared_store(tmp_path)
    run_prompt_extraction_stage(config, store, force=False)  # type: ignore[arg-type]
    input_path = store.path("inputs", "prompts.jsonl")
    outputs = _prompt_extraction_outputs(store)
    manifest_path = store.path(".stages", "extract-prompt-tsg.json")
    protected = (*outputs, manifest_path)
    previous = tuple(path.read_bytes() for path in protected)
    original_input = input_path.read_bytes()
    changed_records = [
        json.loads(line) for line in original_input.decode("utf-8").splitlines() if line.strip()
    ]
    changed_records[0]["prompt"] += " Include the file metadata in the return value."
    changed_input = (
        "\n".join(
            json.dumps(record, ensure_ascii=False, separators=(",", ":"))
            for record in changed_records
        )
        + "\n"
    ).encode("utf-8")
    assert changed_input != original_input

    real_begin = jsonl_stage_module.ArtifactTransaction.begin
    real_factory = stage_module.extractor_for_config
    write_changed = threading.Event()
    changed_written = threading.Event()
    write_original = threading.Event()
    original_written = threading.Event()
    writer_errors: list[BaseException] = []
    restored = False

    def external_writer() -> None:
        nonlocal restored
        try:
            if not write_changed.wait(timeout=5):
                raise AssertionError("external rewrite was not requested")
            input_path.write_bytes(changed_input)
            changed_written.set()
            if not write_original.wait(timeout=5):
                raise AssertionError("external restore was not requested")
            input_path.write_bytes(original_input)
            restored = True
        except BaseException as error:
            writer_errors.append(error)
        finally:
            changed_written.set()
            original_written.set()

    writer = threading.Thread(target=external_writer, daemon=True)
    writer.start()

    def begin_with_external_rewrite(
        journal_path: Path,
        artifacts: tuple[object, ...],
    ) -> object:
        transaction = real_begin(journal_path, artifacts)  # type: ignore[arg-type]
        write_changed.set()
        if not changed_written.wait(timeout=5) or writer_errors:
            raise AssertionError("external rewrite failed")
        return transaction

    class RestoringExtractor:
        def __init__(self, nested: object) -> None:
            self.nested = nested

        def extract(self, prompt: object, policy: object) -> object:
            if not restored:
                write_original.set()
                if not original_written.wait(timeout=5) or writer_errors:
                    raise AssertionError("external restore failed")
            return self.nested.extract(prompt, policy)  # type: ignore[attr-defined]

    def construct_restoring_extractor(*args: object, **kwargs: object) -> RestoringExtractor:
        return RestoringExtractor(real_factory(*args, **kwargs))  # type: ignore[arg-type]

    monkeypatch.setattr(
        jsonl_stage_module.ArtifactTransaction,
        "begin",
        staticmethod(begin_with_external_rewrite),
    )
    monkeypatch.setattr(stage_module, "extractor_for_config", construct_restoring_extractor)

    try:
        with pytest.raises(SecAwareError) as exc_info:
            run_prompt_extraction_stage(config, store, force=True)  # type: ignore[arg-type]
    finally:
        write_changed.set()
        write_original.set()
        writer.join(timeout=5)

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert not writer.is_alive()
    assert not writer_errors
    assert restored
    assert input_path.read_bytes() == original_input
    assert tuple(path.read_bytes() for path in protected) == previous
    assert not store.path(".stages", ".extract-prompt-tsg.transaction.json").exists()
    assert not list(store.root.rglob("*.recovery.backup"))
    assert not list(store.path("tsg").glob(".*.stage.candidate"))
    assert not store.stage_is_active("extract-prompt-tsg")


@pytest.mark.parametrize("signal_type", [KeyboardInterrupt, SystemExit])
def test_post_install_canonical_readback_interrupt_restores_complete_prior_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signal_type: type[BaseException],
) -> None:
    config, store = _prepared_store(tmp_path)
    run_prompt_extraction_stage(config, store, force=False)  # type: ignore[arg-type]
    outputs = _prompt_extraction_outputs(store)
    manifest_path = store.path(".stages", "extract-prompt-tsg.json")
    protected = (*outputs, manifest_path)
    previous = tuple(path.read_bytes() for path in protected)
    real_readback = jsonl_stage_module._read_jsonl_output
    calls: list[Path] = []

    def interrupt_post_install(
        spec: object,
        path: Path,
        *,
        stage: str,
    ) -> object:
        calls.append(path)
        if len(calls) == len(outputs) + 1:
            assert path == outputs[0]
            assert all(output.exists() for output in outputs)
            raise signal_type("post-install canonical readback interrupted")
        return real_readback(spec, path, stage=stage)  # type: ignore[arg-type]

    monkeypatch.setattr(jsonl_stage_module, "_read_jsonl_output", interrupt_post_install)
    with pytest.raises(signal_type):
        run_prompt_extraction_stage(config, store, force=True)  # type: ignore[arg-type]

    assert len(calls) == len(outputs) + 1
    assert tuple(path.read_bytes() for path in protected) == previous
    assert not store.path(".stages", ".extract-prompt-tsg.transaction.json").exists()
    assert not list(store.root.rglob("*.recovery.backup"))
    assert not list(store.path("tsg").glob(".*.stage.candidate"))
    assert not store.stage_is_active("extract-prompt-tsg")


@pytest.mark.parametrize(
    "selected_backend",
    [
        PromptExtractorBackend.LLM_FACTS_V1,
        PromptExtractorBackend.LLM_DIRECT_GRAPH_V1,
    ],
)
def test_real_factory_never_constructs_or_calls_fallback_after_selected_llm_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    selected_backend: PromptExtractorBackend,
) -> None:
    original_config, original_store = _prepared_store(tmp_path)
    run_prompt_extraction_stage(original_config, original_store, force=False)  # type: ignore[arg-type]
    outputs = _prompt_extraction_outputs(original_store)
    manifest_path = original_store.path(".stages", "extract-prompt-tsg.json")
    protected = (*outputs, manifest_path)
    previous = tuple(path.read_bytes() for path in protected)

    selected_config = _llm_config(original_config, selected_backend)  # type: ignore[arg-type]
    selected_store = RunStore(selected_config)
    selected_store.prepare()
    unexpected = {"deterministic": 0, "facts": 0, "direct": 0}

    def fail_if_constructed(name: str):
        def constructor(*args: object, **kwargs: object) -> object:
            del args, kwargs
            unexpected[name] += 1
            raise AssertionError(f"unexpected {name} fallback construction")

        return constructor

    monkeypatch.setattr(
        extractor_factory_module,
        "DeterministicCatalogExtractor",
        fail_if_constructed("deterministic"),
    )
    if selected_backend is PromptExtractorBackend.LLM_FACTS_V1:
        monkeypatch.setattr(
            extractor_factory_module,
            "LLMDirectGraphExtractor",
            fail_if_constructed("direct"),
        )
    else:
        monkeypatch.setattr(
            extractor_factory_module,
            "LLMFactsExtractor",
            fail_if_constructed("facts"),
        )
    transport = _FailingTransport()

    with pytest.raises(SecAwareError):
        run_prompt_extraction_stage(
            selected_config,
            selected_store,
            force=True,
            transport=transport,
        )

    assert transport.calls == 1
    assert unexpected == {"deterministic": 0, "facts": 0, "direct": 0}
    assert tuple(path.read_bytes() for path in protected) == previous
    assert not selected_store.stage_is_active("extract-prompt-tsg")


def test_prompt_extraction_policy_drift_invalidates_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secaware.pipeline.stages import prompt_extraction as stage_module

    config, store = _prepared_store(tmp_path)
    run_prompt_extraction_stage(config, store, force=False)  # type: ignore[arg-type]
    baseline = extraction_policy(config.tsg)  # type: ignore[union-attr]
    calls = 0
    real_factory = stage_module.extractor_for_config
    real_policy = stage_module.extraction_policy

    class CountingExtractor:
        def __init__(self, nested: object) -> None:
            self.nested = nested

        def extract(self, prompt: object, policy: object) -> object:
            nonlocal calls
            calls += 1
            return self.nested.extract(prompt, policy)  # type: ignore[attr-defined]

    monkeypatch.setattr(
        stage_module,
        "extractor_for_config",
        lambda *args, **kwargs: CountingExtractor(real_factory(*args, **kwargs)),
    )
    monkeypatch.setattr(
        stage_module,
        "extraction_policy",
        lambda value: replace(real_policy(value), policy_sha256="f" * 64),
    )

    run_prompt_extraction_stage(config, store, force=False)  # type: ignore[arg-type]
    assert calls == len(_prompt_records(store))
    manifest = read_stage_manifest(store.path(".stages", "extract-prompt-tsg.json"))
    assert manifest.policy_sha256 == "f" * 64
    assert manifest.policy_sha256 != baseline.policy_sha256


def test_prompt_tsg_contract_digest_binds_extractor_schema_and_catalog_versions() -> None:
    baseline = build_prompt_tsg_stage_contract_sha256()

    assert (
        build_prompt_tsg_stage_contract_sha256(
            extractor_version=PROMPT_TSG_EXTRACTOR_VERSION + ".next"
        )
        != baseline
    )
    assert (
        build_prompt_tsg_stage_contract_sha256(schema_version=TSG_SCHEMA_VERSION + ".next")
        != baseline
    )
    assert build_prompt_tsg_stage_contract_sha256(catalog_sha256="0" * 64) != baseline


@pytest.mark.parametrize(
    ("contract_field", "replacement"),
    [
        ("facts_template_sha256", "0" * 64),
        ("facts_output_schema_sha256", "1" * 64),
        ("direct_template_sha256", "2" * 64),
        ("direct_output_schema_sha256", "3" * 64),
    ],
)
def test_each_template_and_schema_digest_invalidates_records_and_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    contract_field: str,
    replacement: str,
) -> None:
    config, store = _prepared_store(tmp_path)
    run_prompt_extraction_stage(config, store, force=False)  # type: ignore[arg-type]
    baseline = build_prompt_tsg_stage_contract_sha256()
    changed = build_prompt_tsg_stage_contract_sha256(
        **{contract_field: replacement},
    )
    assert changed != baseline

    prompts = tuple(_prompt_records(store))
    proposals = tuple(
        read_jsonl(
            store.path("tsg", "prompt_extraction_proposals.jsonl"),
            PromptExtractionProposalRecord,
            required=True,
            allow_empty=False,
        )
    )
    graphs = tuple(
        read_jsonl(
            store.path("tsg", "prompt_tsg.jsonl"),
            PromptTSGRecord,
            required=True,
            allow_empty=False,
        )
    )
    stale_proposals = tuple(
        proposal.model_copy(update={"policy_sha256": changed}) for proposal in proposals
    )
    stale_graphs = tuple(
        graph.model_copy(update={"extractor_policy_sha256": changed}) for graph in graphs
    )
    with pytest.raises(SecAwareError) as exc_info:
        validate_exact_extraction_coverage(
            prompts,
            stale_proposals,
            stale_graphs,
            extraction_policy(config.tsg),  # type: ignore[union-attr]
        )
    assert exc_info.value.code is ErrorCode.CONTRACT

    monkeypatch.setattr(
        run_store_module,
        "PROMPT_TSG_STAGE_CONTRACT_SHA256",
        changed,
    )
    assert not store.should_skip_stage(
        "extract-prompt-tsg",
        [store.path("inputs", "prompts.jsonl")],
        _prompt_extraction_outputs(store),
        force=False,
        policy_sha256=extraction_policy(config.tsg).policy_sha256,  # type: ignore[union-attr]
        catalog_sha256=PROMPT_TSG_CATALOG_SHA256,
        preserve_committed=True,
    )
    store.abort_stage("extract-prompt-tsg")


def test_prompt_tsg_committed_output_rejects_catalog_mismatch(tmp_path: Path) -> None:
    config, store = _prepared_store(tmp_path)
    extract_prompt_tsg_stage(config, store, force=False)  # type: ignore[arg-type]

    with pytest.raises(SecAwareError) as exc_info:
        with store.hold_committed_output(
            "extract-prompt-tsg",
            _prompt_extraction_outputs(store),
            expected_catalog_sha256="0" * 64,
        ):
            pytest.fail("catalog mismatch was accepted")

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT


def test_prompt_tsg_input_aware_committed_gate_requires_expected_catalog(
    tmp_path: Path,
) -> None:
    config, store = _prepared_store(tmp_path)
    extract_prompt_tsg_stage(config, store, force=False)  # type: ignore[arg-type]
    inputs = [store.path("inputs", "prompts.jsonl")]
    outputs = _prompt_extraction_outputs(store)

    expected = store.require_committed_stage(
        "extract-prompt-tsg",
        inputs,
        outputs,
        expected_catalog_sha256=PROMPT_TSG_CATALOG_SHA256,
    )
    with store.hold_committed_stage(
        "extract-prompt-tsg",
        inputs,
        outputs,
        expected_catalog_sha256=PROMPT_TSG_CATALOG_SHA256,
    ) as held:
        assert held == expected

    for catalog_sha256 in (None, "0" * 64):
        with pytest.raises(SecAwareError) as exc_info:
            store.require_committed_stage(
                "extract-prompt-tsg",
                inputs,
                outputs,
                expected_catalog_sha256=catalog_sha256,
            )
        assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT


def test_prompt_tsg_committed_output_rejects_real_output_tamper(tmp_path: Path) -> None:
    config, store = _prepared_store(tmp_path)
    extract_prompt_tsg_stage(config, store, force=False)  # type: ignore[arg-type]
    output = store.path("tsg", "prompt_tsg.jsonl")
    output.write_bytes(output.read_bytes() + b"\n")

    with pytest.raises(SecAwareError) as exc_info:
        with store.hold_committed_output(
            "extract-prompt-tsg",
            _prompt_extraction_outputs(store),
            expected_catalog_sha256=PROMPT_TSG_CATALOG_SHA256,
        ):
            pytest.fail("tampered Prompt TSG output was accepted")

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT


def test_prompt_tsg_producer_lease_blocks_real_concurrent_force(
    tmp_path: Path,
) -> None:
    config, owner = _prepared_store(tmp_path)
    extract_prompt_tsg_stage(config, owner, force=False)  # type: ignore[arg-type]
    contender = RunStore(config)  # type: ignore[arg-type]
    outputs = _prompt_extraction_outputs(owner)

    with owner.hold_committed_output(
        "extract-prompt-tsg",
        outputs,
        expected_catalog_sha256=PROMPT_TSG_CATALOG_SHA256,
    ):
        with pytest.raises(SecAwareError) as exc_info:
            extract_prompt_tsg_stage(config, contender, force=True)  # type: ignore[arg-type]

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    extract_prompt_tsg_stage(config, contender, force=True)  # type: ignore[arg-type]


def test_prompt_tsg_manifest_tamper_is_not_skippable(tmp_path: Path) -> None:
    config, store = _prepared_store(tmp_path)
    extract_prompt_tsg_stage(config, store, force=False)  # type: ignore[arg-type]
    manifest_path = store.path(".stages", "extract-prompt-tsg.json")
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["catalog_sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")

    assert not store.should_skip_stage(
        "extract-prompt-tsg",
        [store.path("inputs", "prompts.jsonl")],
        _prompt_extraction_outputs(store),
        False,
        policy_sha256=extraction_policy(config.tsg).policy_sha256,  # type: ignore[union-attr]
        catalog_sha256=PROMPT_TSG_CATALOG_SHA256,
        preserve_committed=True,
    )
    store.abort_stage("extract-prompt-tsg")


def test_removed_graph_extraction_command_is_absent_from_cli_help() -> None:
    help_result = CliRunner().invoke(app, ["--help"])
    removed_command = "extract-" + "code-" + "tsg"

    assert help_result.exit_code == 0
    assert removed_command not in help_result.output


@pytest.mark.parametrize(
    "failure",
    [RuntimeError("private-failure"), KeyboardInterrupt("private-interrupt")],
    ids=["error", "interrupt"],
)
def test_prompt_tsg_force_failure_restores_committed_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: BaseException,
) -> None:
    from secaware.pipeline.stages import prompt_extraction as stage_module

    config, store = _prepared_store(tmp_path)
    extract_prompt_tsg_stage(config, store, force=False)  # type: ignore[arg-type]
    outputs = _prompt_extraction_outputs(store)
    manifest_path = store.path(".stages", "extract-prompt-tsg.json")
    previous = tuple(path.read_bytes() for path in (*outputs, manifest_path))

    class FailingExtractor:
        def extract(self, prompt: object, policy: object) -> object:
            del prompt, policy
            raise failure

    monkeypatch.setattr(
        stage_module,
        "extractor_for_config",
        lambda *_args, **_kwargs: FailingExtractor(),
    )

    with pytest.raises(type(failure)):
        extract_prompt_tsg_stage(config, store, force=True)  # type: ignore[arg-type]

    assert tuple(path.read_bytes() for path in (*outputs, manifest_path)) == previous
    with store.hold_committed_output(
        "extract-prompt-tsg",
        outputs,
        expected_catalog_sha256=PROMPT_TSG_CATALOG_SHA256,
    ):
        pass
    assert not store.stage_is_active("extract-prompt-tsg")


def test_prompt_tsg_stage_contract_change_invalidates_skip_only_for_prompt_stage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = _prepared_store(tmp_path)
    extract_prompt_tsg_stage(config, store, force=False)  # type: ignore[arg-type]
    prompt_input = store.path("inputs", "prompts.jsonl")
    prompt_outputs = _prompt_extraction_outputs(store)
    unrelated_output = store.path("reports", "result.txt")
    unrelated_output.write_text("ready\n", encoding="utf-8")
    assert not store.should_skip_stage(
        "test-report", [prompt_input], [unrelated_output], force=False
    )
    store.record_stage("test-report", [prompt_input], [unrelated_output])
    unrelated_fingerprint = store.stage_fingerprint("test-report", [prompt_input])

    monkeypatch.setattr(
        run_store_module,
        "PROMPT_TSG_STAGE_CONTRACT_SHA256",
        "f" * 64,
        raising=False,
    )

    assert not store.should_skip_stage(
        "extract-prompt-tsg",
        [prompt_input],
        prompt_outputs,
        force=False,
        policy_sha256=extraction_policy(config.tsg).policy_sha256,  # type: ignore[union-attr]
        catalog_sha256=PROMPT_TSG_CATALOG_SHA256,
        preserve_committed=True,
    )
    store.abort_stage("extract-prompt-tsg")
    assert store.stage_fingerprint("test-report", [prompt_input]) == unrelated_fingerprint
    assert store.should_skip_stage("test-report", [prompt_input], [unrelated_output], force=False)


def test_prompt_tsg_seal_rejection_retains_lease_until_rollback_finishes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, owner = _prepared_store(tmp_path)
    extract_prompt_tsg_stage(config, owner, force=False)  # type: ignore[arg-type]
    contender = RunStore(config)  # type: ignore[arg-type]
    output = owner.path("tsg", "prompt_tsg.jsonl")
    manifest_path = owner.path(".stages", "extract-prompt-tsg.json")
    pair_outputs = _prompt_extraction_outputs(owner)
    previous = tuple(path.read_bytes() for path in (*pair_outputs, manifest_path))
    inputs = [owner.path("inputs", "prompts.jsonl")]
    outputs = pair_outputs
    rollback_entered = threading.Event()
    allow_rollback = threading.Event()
    owner_done = threading.Event()
    owner_errors: list[BaseException] = []
    real_verify = owner.verify_sealed_outputs
    real_recover = jsonl_stage_module.recover_transaction

    def tamper_after_seal(*args: object, **kwargs: object) -> None:
        output.write_bytes(output.read_bytes() + b"\n")
        real_verify(*args, **kwargs)  # type: ignore[arg-type]

    def blocked_recover(transaction: object) -> None:
        rollback_entered.set()
        if not allow_rollback.wait(timeout=5):
            raise AssertionError("rollback was not released")
        real_recover(transaction)  # type: ignore[arg-type]

    def run_owner() -> None:
        try:
            extract_prompt_tsg_stage(config, owner, force=True)  # type: ignore[arg-type]
        except BaseException as error:
            owner_errors.append(error)
        finally:
            owner_done.set()

    monkeypatch.setattr(owner, "verify_sealed_outputs", tamper_after_seal)
    monkeypatch.setattr(jsonl_stage_module, "recover_transaction", blocked_recover)
    thread = threading.Thread(target=run_owner, daemon=True)
    thread.start()
    assert rollback_entered.wait(timeout=5)

    contender_entered = False
    try:
        contender_entered = not contender.should_skip_stage(
            "extract-prompt-tsg",
            inputs,
            outputs,
            force=True,
            policy_sha256=extraction_policy(config.tsg).policy_sha256,  # type: ignore[union-attr]
            catalog_sha256=PROMPT_TSG_CATALOG_SHA256,
            preserve_committed=True,
        )
    except SecAwareError as error:
        assert error.code is ErrorCode.MANIFEST_CONFLICT
    finally:
        if contender.stage_is_active("extract-prompt-tsg"):
            contender.abort_stage("extract-prompt-tsg")
        allow_rollback.set()

    assert owner_done.wait(timeout=5)
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert contender_entered is False
    assert len(owner_errors) == 1
    assert isinstance(owner_errors[0], SecAwareError)
    assert tuple(path.read_bytes() for path in (*pair_outputs, manifest_path)) == previous
    assert not owner.stage_is_active("extract-prompt-tsg")

    assert not contender.should_skip_stage(
        "extract-prompt-tsg",
        inputs,
        outputs,
        force=True,
        policy_sha256=extraction_policy(config.tsg).policy_sha256,  # type: ignore[union-attr]
        catalog_sha256=PROMPT_TSG_CATALOG_SHA256,
        preserve_committed=True,
    )
    contender.abort_stage("extract-prompt-tsg")

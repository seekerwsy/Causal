from collections.abc import Sequence
import json
import os
from pathlib import Path
import traceback

import pytest
from typer.testing import CliRunner

from secaware import cli as cli_module
from secaware.cli import (
    app,
    extract_code_tsg_stage,
    import_generation_stage,
    plan_generation_stage,
    run_oracle_stage,
)
from secaware.config import AppConfig, write_resolved_config
from secaware.errors import ErrorCode, SecAwareError
from secaware.extractors.code_tsg_extractor import extract_code_tsg
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.io.run_store import RunStore
from secaware.oracle import aggregator as aggregator_module
from secaware.oracle.runner import AnalyzerProcessResult
from secaware.pipeline.manifest import read_stage_manifest
from secaware.schema.generation import (
    GenerationProvenance,
    GenerationRequestRecord,
    OfflineGenerationResultRecord,
    sha256_text,
)
from secaware.schema.hypotheses import FactorType
from secaware.schema.interventions import InterventionRecord
from secaware.schema.records import CanonicalGeneratedCodeRecord, PromptRecord


def _clean_oracle_runner(
    argv: Sequence[str],
    *,
    cwd: Path,
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> AnalyzerProcessResult:
    del timeout_seconds, max_stdout_bytes, max_stderr_bytes
    call = tuple(argv)
    analyzer = "semgrep" if "semgrep" in call[0] else "bandit"
    if call[1:] == ("--version",):
        output = (
            b"1.168.0\n"
            if analyzer == "semgrep"
            else (
                b"bandit 1.9.4\n"
                b"  python version = 3.12.13 (main) [MSC v.1944 64 bit (AMD64)]\n"
            )
        )
        return AnalyzerProcessResult(0, output, "a" * 64)
    files = sorted(path.name for path in cwd.iterdir() if path.suffix == ".py")
    if analyzer == "semgrep":
        payload = {
            "version": "1.168.0",
            "results": [],
            "errors": [],
            "paths": {"scanned": files},
            "skipped_rules": [],
        }
    else:
        metrics = {
            filename: {"loc": 2, "nosec": 0, "skipped_tests": 0}
            for filename in files
        }
        metrics["_totals"] = {"loc": 2, "nosec": 0, "skipped_tests": 0}
        payload = {"errors": [], "metrics": metrics, "results": []}
    return AnalyzerProcessResult(0, json.dumps(payload).encode(), "a" * 64)


def _prompt(prompt_id: str, split: str, text: str) -> PromptRecord:
    return PromptRecord(
        prompt_id=prompt_id,
        split=split,
        language="python",
        task_family="path_handling",
        cwe="CWE-22",
        prompt=text,
    )


def _config(tmp_path: Path, prompts_path: Path) -> AppConfig:
    return AppConfig.model_validate(
        {
            "run": {"name": "offline-generation", "output_dir": str(tmp_path / "run")},
            "data": {"prompts_path": str(prompts_path)},
            "generation": {
                "provider": "mock",
                "models": ["model-b", "model-a"],
                "seeds": [2, 1],
            },
        }
    )


def _prepared_store(tmp_path: Path) -> tuple[AppConfig, RunStore, list[PromptRecord]]:
    prompts = [
        _prompt("prompt-observed", "discover", "Read a user supplied path."),
        _prompt("prompt-counterfactual", "confirm", "Open a user supplied path."),
    ]
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
        counterfactual_prompt="Normalize and constrain the path before opening it.",
        patch_success=True,
        round_trip_valid=True,
        semantic_valid=True,
        target_changed=True,
        side_effect=False,
    )


def _result(
    request: GenerationRequestRecord,
    *,
    code: str | None = None,
) -> OfflineGenerationResultRecord:
    generated_code = code or f"def generated_{request.seed_id}():\n    return {request.seed_id}\n"
    payload = request.model_dump(mode="python", round_trip=True, warnings=False)
    payload.update(
        code=generated_code,
        code_sha256=sha256_text(generated_code),
        provenance=GenerationProvenance(
            producer="offline-test-worker",
            producer_version="1.0",
            source_batch_id="batch-a",
        ),
    )
    return OfflineGenerationResultRecord.model_validate(payload)


def _plan_observed(
    config: AppConfig,
    store: RunStore,
) -> tuple[Path, list[GenerationRequestRecord]]:
    plan_generation_stage(config, store, condition="observed", force=False)
    ledger = store.path("generation", "observed_requests.jsonl")
    requests = read_jsonl(
        ledger,
        GenerationRequestRecord,
        required=True,
        allow_empty=False,
        stage="test-generation-ledger",
    )
    return ledger, requests  # type: ignore[return-value]


def _error_surfaces(error: SecAwareError) -> tuple[str, ...]:
    return (
        str(error),
        "".join(traceback.format_exception(error)),
        json.dumps(error.to_dict(), sort_keys=True),
    )


def _assert_safe_error(error: SecAwareError, *hidden: str) -> None:
    assert error.__cause__ is None
    assert error.__context__ is None
    for value in hidden:
        assert all(value not in surface for surface in _error_surfaces(error))


def test_plan_observed_writes_deterministic_fixed_path_ledger_and_manifest(
    tmp_path: Path,
) -> None:
    config, store, _ = _prepared_store(tmp_path)

    plan_generation_stage(config, store, condition="observed", force=False)

    output = store.path("generation", "observed_requests.jsonl")
    assert output.is_file()
    baseline = output.read_bytes()
    records = read_jsonl(output, GenerationRequestRecord, required=True, allow_empty=False)
    assert len(records) == 8
    assert all(record.endpoint_type == "offline" for record in records)
    assert all(record.system_template_version == "none" for record in records)
    assert all(record.system_template_sha256 == sha256_text("") for record in records)
    assert all(record.parameters.values == {} for record in records)
    manifest = read_stage_manifest(store.path(".stages", "plan-generation-observed.json"))
    assert manifest.outputs == ["generation/observed_requests.jsonl"]

    plan_generation_stage(config, store, condition="observed", force=False)
    assert output.read_bytes() == baseline
    output.write_text("tampered-ledger\n", encoding="utf-8")
    plan_generation_stage(config, store, condition="observed", force=False)
    assert output.read_bytes() == baseline
    plan_generation_stage(config, store, condition="observed", force=True)
    assert output.read_bytes() == baseline


def test_generation_artifact_reads_apply_central_character_budgets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    real_read = cli_module.read_jsonl
    read_limits: list[tuple[object, object]] = []

    def capture_limits(*args: object, **kwargs: object) -> object:
        read_limits.append(
            (kwargs.get("max_line_chars"), kwargs.get("max_total_chars"))
        )
        return real_read(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(cli_module, "read_jsonl", capture_limits)

    plan_generation_stage(config, store, condition="observed", force=False)

    assert read_limits
    assert set(read_limits) == {(8 * 1024 * 1024, 512 * 1024 * 1024)}


def test_generation_skip_wrapper_preserves_an_active_stage_on_reentry(
    tmp_path: Path,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    del config
    stage = "plan-generation-observed"
    inputs = [store.path("inputs", "prompts.jsonl")]
    output = store.path("generation", "observed_requests.jsonl")
    outputs = [output]
    assert store.should_skip_stage(stage, inputs, outputs, force=False) is False

    with pytest.raises(SecAwareError) as exc_info:
        cli_module._generation_stage_should_skip(
            store,
            stage,
            inputs,
            outputs,
            force=False,
        )

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    output.write_text("active execution output\n", encoding="utf-8")
    store.seal_stage_outputs(stage, outputs)
    store.record_stage(stage, inputs, outputs)
    assert store.path(".stages", f"{stage}.json").exists()


def test_plan_counterfactual_uses_fixed_inputs_and_preserves_coordinates(
    tmp_path: Path,
) -> None:
    config, store, prompts = _prepared_store(tmp_path)
    intervention = _intervention(prompts[1])
    write_jsonl(store.path("interventions", "interventions.jsonl"), [intervention])

    plan_generation_stage(config, store, condition="counterfactual", force=False)

    output = store.path("generation", "counterfactual_requests.jsonl")
    records = read_jsonl(
        output,
        GenerationRequestRecord,
        required=True,
        allow_empty=False,
    )
    assert len(records) == 4
    assert all(record.condition == "counterfactual" for record in records)
    assert all(record.intervention_id == intervention.intervention_id for record in records)
    assert all(record.hypothesis_id == intervention.hypothesis_id for record in records)
    manifest = read_stage_manifest(
        store.path(".stages", "plan-generation-counterfactual.json")
    )
    assert set(manifest.inputs) == {
        "inputs/prompts.jsonl",
        "interventions/interventions.jsonl",
    }


def test_plan_reads_back_ledger_before_recording_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    output = store.path("generation", "observed_requests.jsonl")
    real_write = cli_module.write_jsonl

    def write_then_corrupt(path: Path, records: object, **kwargs: object) -> None:
        real_write(path, records, **kwargs)  # type: ignore[arg-type]
        Path(path).write_text("not-json\n", encoding="utf-8")

    monkeypatch.setattr(cli_module, "write_jsonl", write_then_corrupt)

    with pytest.raises(SecAwareError) as exc_info:
        plan_generation_stage(config, store, condition="observed", force=False)

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert output.read_text(encoding="utf-8") == "not-json\n"
    assert not store.path(".stages", "plan-generation-observed.json").exists()
    with pytest.raises(SecAwareError) as record_error:
        store.record_stage(
            "plan-generation-observed",
            [store.path("inputs", "prompts.jsonl")],
            [output],
        )
    assert record_error.value.code is ErrorCode.MANIFEST_CONFLICT


def test_plan_rejects_valid_ledger_replacement_after_output_seal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    output = store.path("generation", "observed_requests.jsonl")
    manifest_path = store.path(".stages", "plan-generation-observed.json")
    real_seal = store.seal_stage_outputs

    def seal_then_reverse(stage: str, outputs: list[Path]) -> None:
        real_seal(stage, outputs)
        records = read_jsonl(
            output,
            GenerationRequestRecord,
            required=True,
            allow_empty=False,
        )
        write_jsonl(output, list(reversed(records)))

    monkeypatch.setattr(store, "seal_stage_outputs", seal_then_reverse)

    with pytest.raises(SecAwareError) as exc_info:
        plan_generation_stage(config, store, condition="observed", force=False)

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert not manifest_path.exists()
    with pytest.raises(SecAwareError) as record_info:
        store.record_stage(
            "plan-generation-observed",
            [store.path("inputs", "prompts.jsonl")],
            [output],
        )
    assert record_info.value.code is ErrorCode.MANIFEST_CONFLICT


def test_import_rejects_valid_canonical_replacement_after_output_seal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    ledger, requests = _plan_observed(config, store)
    results_path = tmp_path / "external-results.jsonl"
    write_jsonl(results_path, [_result(request) for request in requests])
    output = store.path("generation", "observed_code.jsonl")
    manifest_path = store.path(".stages", "import-generation-observed.json")
    real_seal = store.seal_stage_outputs

    def seal_then_reverse(stage: str, outputs: list[Path]) -> None:
        real_seal(stage, outputs)
        records = read_jsonl(
            output,
            CanonicalGeneratedCodeRecord,
            required=True,
            allow_empty=False,
        )
        write_jsonl(output, list(reversed(records)))

    monkeypatch.setattr(store, "seal_stage_outputs", seal_then_reverse)

    with pytest.raises(SecAwareError) as exc_info:
        import_generation_stage(
            config,
            store,
            condition="observed",
            results_path=results_path,
            force=False,
        )

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert not manifest_path.exists()
    with pytest.raises(SecAwareError) as record_info:
        store.record_stage(
            "import-generation-observed",
            [ledger, results_path],
            [output],
        )
    assert record_info.value.code is ErrorCode.MANIFEST_CONFLICT


@pytest.mark.parametrize("stage_kind", ["plan", "import"])
@pytest.mark.parametrize("replacement", ["invalid_json", "invalid_schema"])
def test_post_seal_invalid_output_replacement_is_a_manifest_conflict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage_kind: str,
    replacement: str,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    if stage_kind == "plan":
        stage = "plan-generation-observed"
        output = store.path("generation", "observed_requests.jsonl")
        inputs = [store.path("inputs", "prompts.jsonl")]

        def run_stage() -> None:
            plan_generation_stage(config, store, condition="observed", force=False)

    else:
        ledger, requests = _plan_observed(config, store)
        results_path = tmp_path / "external-results.jsonl"
        write_jsonl(results_path, [_result(request) for request in requests])
        stage = "import-generation-observed"
        output = store.path("generation", "observed_code.jsonl")
        inputs = [ledger, results_path]

        def run_stage() -> None:
            import_generation_stage(
                config,
                store,
                condition="observed",
                results_path=results_path,
                force=False,
            )

    manifest_path = store.path(".stages", f"{stage}.json")
    secret = f"private-{stage_kind}-{replacement}-replacement"
    real_seal = store.seal_stage_outputs

    def seal_then_replace(stage_name: str, outputs: list[Path]) -> None:
        real_seal(stage_name, outputs)
        if replacement == "invalid_json":
            output.write_text(f"not-json-{secret}\n", encoding="utf-8")
        else:
            write_jsonl(output, [{"schema_version": "1.0", "private": secret}])

    monkeypatch.setattr(store, "seal_stage_outputs", seal_then_replace)

    with pytest.raises(SecAwareError) as exc_info:
        run_stage()

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    _assert_safe_error(exc_info.value, secret, str(output))
    assert not manifest_path.exists()
    with pytest.raises(SecAwareError) as record_info:
        store.record_stage(stage, inputs, [output])
    assert record_info.value.code is ErrorCode.MANIFEST_CONFLICT


def test_unchanged_sealed_bytes_preserve_contract_for_readback_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    output = store.path("generation", "observed_requests.jsonl")
    real_read = cli_module._read_generation_records
    verify_calls: list[tuple[str, tuple[Path, ...]]] = []

    def reverse_readback(
        path: Path,
        model: type[object],
        **kwargs: object,
    ) -> list[object]:
        records = real_read(path, model, **kwargs)
        if Path(path) == output and model is GenerationRequestRecord:
            return list(reversed(records))
        return records

    def verify(stage: str, outputs: list[Path]) -> None:
        verify_calls.append((stage, tuple(outputs)))

    monkeypatch.setattr(cli_module, "_read_generation_records", reverse_readback)
    monkeypatch.setattr(store, "verify_sealed_outputs", verify, raising=False)

    with pytest.raises(SecAwareError) as exc_info:
        plan_generation_stage(config, store, condition="observed", force=False)

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert verify_calls == [("plan-generation-observed", (output,))]
    assert not store.path(".stages", "plan-generation-observed.json").exists()


@pytest.mark.parametrize("stage_kind", ["plan", "import"])
def test_generation_stage_rejects_valid_output_reordered_at_record_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage_kind: str,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    if stage_kind == "plan":
        stage = "plan-generation-observed"
        output = store.path("generation", "observed_requests.jsonl")
        inputs = [store.path("inputs", "prompts.jsonl")]
        model: type[GenerationRequestRecord] | type[CanonicalGeneratedCodeRecord] = (
            GenerationRequestRecord
        )

        def run_stage() -> None:
            plan_generation_stage(config, store, condition="observed", force=False)

    else:
        ledger, requests = _plan_observed(config, store)
        results_path = tmp_path / "external-results.jsonl"
        write_jsonl(results_path, [_result(request) for request in requests])
        stage = "import-generation-observed"
        output = store.path("generation", "observed_code.jsonl")
        inputs = [ledger, results_path]
        model = CanonicalGeneratedCodeRecord

        def run_stage() -> None:
            import_generation_stage(
                config,
                store,
                condition="observed",
                results_path=results_path,
                force=False,
            )

    manifest_path = store.path(".stages", f"{stage}.json")
    real_record = store.record_stage

    def reverse_then_record(
        stage_name: str,
        input_paths: list[Path],
        output_paths: list[Path],
    ) -> None:
        records = read_jsonl(output, model, required=True, allow_empty=False)
        write_jsonl(output, list(reversed(records)))
        real_record(stage_name, input_paths, output_paths)

    monkeypatch.setattr(store, "record_stage", reverse_then_record)

    with pytest.raises(SecAwareError) as exc_info:
        run_stage()

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert not manifest_path.exists()
    assert store.should_skip_stage(stage, inputs, [output], force=False) is False
    store.invalidate_stage(stage)


def test_import_shuffled_results_writes_ledger_order_canonical_output(
    tmp_path: Path,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    ledger, requests = _plan_observed(config, store)
    results_path = tmp_path / "external-results.jsonl"
    write_jsonl(results_path, [_result(request) for request in reversed(requests)])

    import_generation_stage(
        config,
        store,
        condition="observed",
        results_path=results_path,
        force=False,
    )

    output = store.path("generation", "observed_code.jsonl")
    records = read_jsonl(
        output,
        CanonicalGeneratedCodeRecord,
        required=True,
        allow_empty=False,
    )
    assert [record.request_id for record in records] == [
        request.request_id for request in requests
    ]
    assert extract_code_tsg(records[0]).code_id == records[0].code_id
    manifest = read_stage_manifest(store.path(".stages", "import-generation-observed.json"))
    assert "generation/observed_requests.jsonl" in manifest.inputs
    external_keys = [path for path in manifest.inputs if path.startswith("@external/")]
    assert len(external_keys) == 1
    rendered_manifest = store.path(
        ".stages", "import-generation-observed.json"
    ).read_text(encoding="utf-8")
    assert str(results_path) not in rendered_manifest
    assert results_path.name not in rendered_manifest
    assert manifest.outputs == ["generation/observed_code.jsonl"]
    assert ledger.is_file()


def test_import_counterfactual_results_preserves_request_coordinates(
    tmp_path: Path,
) -> None:
    config, store, prompts = _prepared_store(tmp_path)
    intervention = _intervention(prompts[1])
    write_jsonl(store.path("interventions", "interventions.jsonl"), [intervention])
    plan_generation_stage(config, store, condition="counterfactual", force=False)
    ledger = store.path("generation", "counterfactual_requests.jsonl")
    requests = read_jsonl(
        ledger,
        GenerationRequestRecord,
        required=True,
        allow_empty=False,
    )
    results_path = tmp_path / "counterfactual-results.jsonl"
    write_jsonl(results_path, [_result(request) for request in reversed(requests)])

    import_generation_stage(
        config,
        store,
        condition="counterfactual",
        results_path=results_path,
        force=False,
    )

    records = read_jsonl(
        store.path("generation", "counterfactual_code.jsonl"),
        CanonicalGeneratedCodeRecord,
        required=True,
        allow_empty=False,
    )
    assert [record.request_id for record in records] == [
        request.request_id for request in requests
    ]
    assert all(record.condition == "counterfactual" for record in records)
    assert all(record.intervention_id == intervention.intervention_id for record in records)
    assert all(record.hypothesis_id == intervention.hypothesis_id for record in records)


def test_import_skip_and_force_control_reexecution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    _, requests = _plan_observed(config, store)
    results_path = tmp_path / "external-results.jsonl"
    write_jsonl(results_path, [_result(request) for request in requests])
    import_generation_stage(
        config,
        store,
        condition="observed",
        results_path=results_path,
        force=False,
    )
    real_import = cli_module.import_offline_results
    calls = 0

    def count_imports(
        expected: list[GenerationRequestRecord],
        received: list[OfflineGenerationResultRecord],
    ) -> list[CanonicalGeneratedCodeRecord]:
        nonlocal calls
        calls += 1
        return real_import(expected, received)

    monkeypatch.setattr(cli_module, "import_offline_results", count_imports)

    import_generation_stage(
        config,
        store,
        condition="observed",
        results_path=results_path,
        force=False,
    )
    assert calls == 0

    import_generation_stage(
        config,
        store,
        condition="observed",
        results_path=results_path,
        force=True,
    )
    assert calls == 1


def test_import_invalidates_old_manifest_when_input_snapshot_cannot_be_created(
    tmp_path: Path,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    ledger, requests = _plan_observed(config, store)
    results_path = tmp_path / "external-results.jsonl"
    write_jsonl(results_path, [_result(request) for request in requests])
    import_generation_stage(
        config,
        store,
        condition="observed",
        results_path=results_path,
        force=False,
    )
    output = store.path("generation", "observed_code.jsonl")
    baseline = output.read_bytes()
    manifest_path = store.path(".stages", "import-generation-observed.json")
    assert manifest_path.exists()
    ledger.unlink()

    with pytest.raises(SecAwareError) as exc_info:
        import_generation_stage(
            config,
            store,
            condition="observed",
            results_path=results_path,
            force=False,
        )

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert output.read_bytes() == baseline
    assert not manifest_path.exists()


def test_alternate_manifest_invalidation_failure_invalidates_import_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    _, requests = _plan_observed(config, store)
    results_path = tmp_path / "external-results.jsonl"
    write_jsonl(results_path, [_result(request) for request in requests])
    import_generation_stage(
        config,
        store,
        condition="observed",
        results_path=results_path,
        force=False,
    )
    manifest_path = store.path(".stages", "import-generation-observed.json")
    assert manifest_path.exists()
    real_invalidate = store.invalidate_stage
    secret = "private-alternate-invalidation-failure"

    def fail_alternate(stage: str) -> None:
        if stage == "generate-observed":
            raise SecAwareError(
                code=ErrorCode.MANIFEST_CONFLICT,
                stage=stage,
                message="alternate manifest could not be invalidated",
                details={"secret": secret},
            )
        real_invalidate(stage)

    monkeypatch.setattr(store, "invalidate_stage", fail_alternate)

    with pytest.raises(SecAwareError) as exc_info:
        import_generation_stage(
            config,
            store,
            condition="observed",
            results_path=results_path,
            force=False,
        )

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    _assert_safe_error(exc_info.value, secret)
    assert not manifest_path.exists()


def test_missing_results_is_retryable_and_invalidates_previous_import_manifest(
    tmp_path: Path,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    _, requests = _plan_observed(config, store)
    results_path = tmp_path / "private-external-results.jsonl"
    write_jsonl(results_path, [_result(request) for request in requests])
    import_generation_stage(
        config,
        store,
        condition="observed",
        results_path=results_path,
        force=False,
    )
    output = store.path("generation", "observed_code.jsonl")
    baseline = output.read_bytes()
    manifest_path = store.path(".stages", "import-generation-observed.json")
    assert manifest_path.exists()
    results_path.unlink()

    with pytest.raises(SecAwareError) as exc_info:
        import_generation_stage(
            config,
            store,
            condition="observed",
            results_path=results_path,
            force=False,
        )

    error = exc_info.value
    assert error.code is ErrorCode.EXTERNAL_INPUT_REQUIRED
    assert error.retryable is True
    _assert_safe_error(error, str(results_path), "private-external-results")
    assert output.read_bytes() == baseline
    assert not manifest_path.exists()


@pytest.mark.parametrize("alias_kind", ["output", "ledger", "hardlink"])
def test_import_rejects_results_alias_before_touching_run_artifacts(
    tmp_path: Path,
    alias_kind: str,
) -> None:
    config, store, prompts = _prepared_store(tmp_path)
    ledger, requests = _plan_observed(config, store)
    external_results = tmp_path / "external-results.jsonl"
    write_jsonl(external_results, [_result(request) for request in requests])
    import_generation_stage(
        config,
        store,
        condition="observed",
        results_path=external_results,
        force=False,
    )
    output = store.path("generation", "observed_code.jsonl")
    import_manifest = store.path(".stages", "import-generation-observed.json")
    plan_manifest = store.path(".stages", "plan-generation-observed.json")
    protected_paths = [
        ledger,
        output,
        import_manifest,
        plan_manifest,
        store.path("config.resolved.yaml"),
        store.path("inputs", "prompts.jsonl"),
    ]
    before = {path: path.read_bytes() for path in protected_paths}
    if alias_kind == "output":
        alias = output
    elif alias_kind == "ledger":
        alias = ledger
    else:
        alias = tmp_path / "private-hardlink-results.jsonl"
        os.link(output, alias)

    with pytest.raises(SecAwareError) as exc_info:
        import_generation_stage(
            config,
            store,
            condition="observed",
            results_path=alias,
            force=False,
        )

    assert exc_info.value.code in {ErrorCode.CONTRACT, ErrorCode.CONFIG}
    _assert_safe_error(
        exc_info.value,
        str(alias),
        prompts[0].prompt,
        requests[0].request_id,
    )
    assert {path: path.read_bytes() for path in protected_paths} == before


def test_import_rejects_a_schema_valid_ledger_without_committed_plan_provenance(
    tmp_path: Path,
) -> None:
    config, store, prompts = _prepared_store(tmp_path)
    ledger, requests = _plan_observed(config, store)
    results_path = tmp_path / "external-results.jsonl"
    write_jsonl(results_path, [_result(request) for request in requests])
    import_generation_stage(
        config,
        store,
        condition="observed",
        results_path=results_path,
        force=False,
    )
    output = store.path("generation", "observed_code.jsonl")
    output_bytes = output.read_bytes()
    plan_manifest = store.path(".stages", "plan-generation-observed.json")
    plan_manifest_bytes = plan_manifest.read_bytes()
    import_manifest = store.path(".stages", "import-generation-observed.json")
    assert import_manifest.exists()
    write_jsonl(ledger, list(reversed(requests)))

    with pytest.raises(SecAwareError) as exc_info:
        import_generation_stage(
            config,
            store,
            condition="observed",
            results_path=results_path,
            force=False,
        )

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    _assert_safe_error(
        exc_info.value,
        str(ledger),
        prompts[0].prompt,
        requests[0].request_id,
    )
    assert output.read_bytes() == output_bytes
    assert plan_manifest.read_bytes() == plan_manifest_bytes
    assert not import_manifest.exists()


@pytest.mark.parametrize("consumer", ["extract", "oracle"])
def test_downstream_rejects_old_code_after_partial_import_invalidates_producers(
    tmp_path: Path,
    consumer: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    _, requests = _plan_observed(config, store)
    results_path = tmp_path / "external-results.jsonl"
    write_jsonl(results_path, [_result(request) for request in requests])
    import_generation_stage(
        config,
        store,
        condition="observed",
        results_path=results_path,
        force=False,
    )
    if consumer == "extract":
        consumer_stage = "extract-code-tsg-observed"
        consumer_output = store.path("tsg", "observed_code_tsg.jsonl")
        run_consumer = lambda: extract_code_tsg_stage(  # noqa: E731
            config,
            store,
            condition="observed",
            force=False,
        )
    else:
        monkeypatch.setattr(aggregator_module, "validate_analyzer_runtime", lambda: None)
        consumer_stage = "run-oracle-observed"
        consumer_output = store.path("oracle", "observed_oracle.jsonl")
        run_consumer = lambda: run_oracle_stage(  # noqa: E731
            config,
            store,
            condition="observed",
            force=False,
            runner=_clean_oracle_runner,
            runtime_validator=lambda: None,
        )
    run_consumer()
    consumer_manifest = store.path(".stages", f"{consumer_stage}.json")
    assert consumer_manifest.exists()
    consumer_bytes = consumer_output.read_bytes()
    code_output = store.path("generation", "observed_code.jsonl")
    code_bytes = code_output.read_bytes()
    write_jsonl(results_path, [_result(request) for request in requests[:-1]])

    with pytest.raises(SecAwareError) as import_error:
        import_generation_stage(
            config,
            store,
            condition="observed",
            results_path=results_path,
            force=False,
        )
    assert import_error.value.code is ErrorCode.EXTERNAL_INPUT_REQUIRED
    assert not store.path(".stages", "import-generation-observed.json").exists()
    assert not store.path(".stages", "generate-observed.json").exists()

    with pytest.raises(SecAwareError) as consumer_error:
        run_consumer()

    assert consumer_error.value.code is ErrorCode.MANIFEST_CONFLICT
    _assert_safe_error(consumer_error.value, str(code_output), requests[0].request_id)
    assert code_output.read_bytes() == code_bytes
    assert consumer_output.read_bytes() == consumer_bytes
    assert not consumer_manifest.exists()


def test_partial_results_then_append_completes_without_reordering(
    tmp_path: Path,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    _, requests = _plan_observed(config, store)
    results_path = tmp_path / "partial-results.jsonl"
    output = store.path("generation", "observed_code.jsonl")
    output.write_bytes(b"old-output-bytes")
    partial = [_result(request) for request in requests[:-1]]
    write_jsonl(results_path, partial)

    with pytest.raises(SecAwareError) as exc_info:
        import_generation_stage(
            config,
            store,
            condition="observed",
            results_path=results_path,
            force=False,
        )

    assert exc_info.value.code is ErrorCode.EXTERNAL_INPUT_REQUIRED
    assert exc_info.value.retryable is True
    assert output.read_bytes() == b"old-output-bytes"
    assert not store.path(".stages", "import-generation-observed.json").exists()
    with pytest.raises(SecAwareError) as record_error:
        store.record_stage(
            "import-generation-observed",
            [store.path("generation", "observed_requests.jsonl"), results_path],
            [output],
        )
    assert record_error.value.code is ErrorCode.MANIFEST_CONFLICT

    complete = partial + [_result(requests[-1])]
    write_jsonl(results_path, complete)
    import_generation_stage(
        config,
        store,
        condition="observed",
        results_path=results_path,
        force=False,
    )
    imported = read_jsonl(output, CanonicalGeneratedCodeRecord, required=True)
    assert [record.request_id for record in imported] == [
        request.request_id for request in requests
    ]


@pytest.mark.parametrize("failure", ["duplicate", "extra", "envelope", "code_hash"])
def test_invalid_results_are_contract_errors_and_preserve_existing_output(
    tmp_path: Path,
    failure: str,
) -> None:
    config, store, prompts = _prepared_store(tmp_path)
    _, requests = _plan_observed(config, store)
    results_path = tmp_path / f"private-{failure}-results.jsonl"
    valid = [_result(request) for request in requests]
    secret = f"{failure}-payload-secret"
    if failure == "duplicate":
        payloads: list[object] = valid + [valid[0]]
    elif failure == "extra":
        extra_prompt = _prompt("extra-prompt", "discover", "Extra prompt text.")
        extra_requests = cli_module.plan_observed_requests(
            [extra_prompt],
            ["model-a"],
            [1],
            endpoint_type="offline",
        )
        payloads = valid + [_result(extra_requests[0], code=f"# {secret}\npass\n")]
    else:
        payloads = [result.model_dump(mode="json") for result in valid]
        if failure == "envelope":
            payloads[0]["model_id"] = secret  # type: ignore[index]
        else:
            payloads[0]["code_sha256"] = "0" * 64  # type: ignore[index]
    write_jsonl(results_path, payloads)
    output = store.path("generation", "observed_code.jsonl")
    baseline = b"existing-output-must-survive"
    output.write_bytes(baseline)

    with pytest.raises(SecAwareError) as exc_info:
        import_generation_stage(
            config,
            store,
            condition="observed",
            results_path=results_path,
            force=False,
        )

    error = exc_info.value
    assert error.code is ErrorCode.CONTRACT
    _assert_safe_error(
        error,
        str(results_path),
        secret,
        prompts[0].prompt,
        requests[0].request_id,
        valid[0].code,
        "offline-test-worker",
    )
    assert output.read_bytes() == baseline
    assert not store.path(".stages", "import-generation-observed.json").exists()


@pytest.mark.parametrize("changed_input", ["ledger", "results"])
def test_import_detects_input_change_during_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    changed_input: str,
) -> None:
    config, store, _ = _prepared_store(tmp_path)
    ledger, requests = _plan_observed(config, store)
    results_path = tmp_path / "external-results.jsonl"
    write_jsonl(results_path, [_result(request) for request in requests])
    output = store.path("generation", "observed_code.jsonl")
    real_write = cli_module.write_jsonl

    def write_then_change(path: Path, records: object, **kwargs: object) -> None:
        real_write(path, records, **kwargs)  # type: ignore[arg-type]
        if Path(path) == output:
            target = ledger if changed_input == "ledger" else results_path
            target.write_bytes(target.read_bytes() + b"\n")

    monkeypatch.setattr(cli_module, "write_jsonl", write_then_change)

    with pytest.raises(SecAwareError) as exc_info:
        import_generation_stage(
            config,
            store,
            condition="observed",
            results_path=results_path,
            force=False,
        )

    assert exc_info.value.code is ErrorCode.MANIFEST_CONFLICT
    assert not store.path(".stages", "import-generation-observed.json").exists()


def test_tampered_canonical_output_is_rebuilt_in_ledger_order(tmp_path: Path) -> None:
    config, store, _ = _prepared_store(tmp_path)
    _, requests = _plan_observed(config, store)
    results_path = tmp_path / "external-results.jsonl"
    write_jsonl(results_path, [_result(request) for request in requests])
    import_generation_stage(
        config,
        store,
        condition="observed",
        results_path=results_path,
        force=False,
    )
    output = store.path("generation", "observed_code.jsonl")
    baseline = output.read_bytes()
    output.write_text("tampered-output\n", encoding="utf-8")

    import_generation_stage(
        config,
        store,
        condition="observed",
        results_path=results_path,
        force=False,
    )

    assert output.read_bytes() == baseline


def test_cli_missing_results_and_invalid_condition_are_safe(tmp_path: Path) -> None:
    config, store, _ = _prepared_store(tmp_path)
    _plan_observed(config, store)
    config_path = tmp_path / "config.yaml"
    write_resolved_config(config, config_path)
    missing_results = tmp_path / "private-missing-results.jsonl"

    missing = CliRunner().invoke(
        app,
        [
            "import-generation",
            "--config",
            str(config_path),
            "--condition",
            "observed",
            "--results",
            str(missing_results),
        ],
    )
    assert missing.exit_code == int(ErrorCode.EXTERNAL_INPUT_REQUIRED)
    assert str(missing_results) not in missing.output + missing.stderr
    assert "Traceback" not in missing.output + missing.stderr

    invalid_secret = "private-invalid-condition"
    invalid = CliRunner().invoke(
        app,
        [
            "plan-generation",
            "--config",
            str(config_path),
            "--condition",
            invalid_secret,
        ],
    )
    assert invalid.exit_code == int(ErrorCode.CONFIG)
    assert invalid_secret not in invalid.output + invalid.stderr
    assert "Traceback" not in invalid.output + invalid.stderr


@pytest.mark.parametrize("command", ["plan-generation", "import-generation"])
def test_offline_generation_cli_help_uses_only_fixed_artifact_paths(command: str) -> None:
    result = CliRunner().invoke(app, [command, "--help"])

    assert result.exit_code == 0, result.output
    assert "--condition" in result.output
    assert "--force" in result.output
    assert "--ledger" not in result.output
    assert "--output" not in result.output
    if command == "import-generation":
        assert "--results" in result.output

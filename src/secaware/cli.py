from collections.abc import Callable
import os
from pathlib import Path
from typing import Literal, Optional, TypeVar, cast

import typer

from secaware.analysis.effects import estimate_effects
from secaware.analysis.pairing import build_pairs
from secaware.commands.common import cli_action
from secaware.config import AppConfig, load_config
from secaware.discovery.tsg_qcd import discover_hypotheses
from secaware.errors import ErrorCode, SecAwareError
from secaware.extractors.code_tsg_extractor import extract_code_tsg
from secaware.extractors.prompt_tsg_extractor import extract_prompt_tsg
from secaware.generation.providers import get_provider
from secaware.generation.request_planner import (
    MAX_GENERATION_AXIS_ITEMS,
    MAX_GENERATION_REQUESTS,
    plan_counterfactual_requests,
    plan_observed_requests,
)
from secaware.generation.result_importer import (
    MAX_OFFLINE_IMPORT_RECORDS,
    import_offline_results,
)
from secaware.intervention.operators import apply_intervention
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.io.run_store import RunStore
from secaware.logging_utils import console
from secaware.oracle.aggregator import run_oracle as run_code_oracle
from secaware.pipeline.preflight import run_preflight
from secaware.reports.tables import write_reports
from secaware.schema.hypotheses import HypothesisRecord
from secaware.schema.generation import GenerationRequestRecord, OfflineGenerationResultRecord
from secaware.schema.interventions import InterventionRecord
from secaware.schema.records import (
    CanonicalGeneratedCodeRecord,
    GeneratedCodeRecord,
    PromptRecord,
)
from secaware.schema.results import EffectRecord, OracleRecord, PairResult
from secaware.schema.tsg import TSGRecord

app = typer.Typer(help="SecAware reproducible prompt-side security mechanism pipeline.")
GenerationCondition = Literal["observed", "counterfactual"]
_Record = TypeVar("_Record")
_ActionResult = TypeVar("_ActionResult")
MAX_GENERATION_JSONL_LINE_CHARS = 8 * 1024 * 1024
MAX_GENERATION_JSONL_TOTAL_CHARS = 512 * 1024 * 1024


def _load(config: Path, run_dir: Optional[Path]) -> tuple[AppConfig, RunStore]:
    loaded = load_config(config, run_dir=run_dir)
    return loaded, RunStore(loaded)


def _prepare(config: AppConfig, store: RunStore) -> None:
    run_preflight(config)
    store.prepare()


def _prompt_records(store: RunStore) -> list[PromptRecord]:
    return read_jsonl(store.path("inputs", "prompts.jsonl"), PromptRecord)  # type: ignore[return-value]


def _generation_condition(value: str) -> GenerationCondition:
    if value == "observed" or value == "counterfactual":
        return cast(GenerationCondition, value)
    raise SecAwareError(
        code=ErrorCode.CONFIG,
        stage="generation",
        message="generation condition is invalid",
    )


def _generation_stage_error(
    code: ErrorCode,
    stage: str,
    message: str,
    *,
    retryable: bool = False,
) -> SecAwareError:
    return SecAwareError(
        code=code,
        stage=stage,
        message=message,
        retryable=retryable,
    )


def _read_generation_records(
    path: Path,
    model: type[_Record],
    *,
    stage: str,
    allow_empty: bool,
    max_records: int,
) -> list[_Record]:
    try:
        records = read_jsonl(
            path,
            model,
            required=True,
            allow_empty=allow_empty,
            max_records=max_records,
            max_line_chars=MAX_GENERATION_JSONL_LINE_CHARS,
            max_total_chars=MAX_GENERATION_JSONL_TOTAL_CHARS,
            stage=stage,
        )
    except (OSError, SecAwareError, UnicodeError):
        pass
    else:
        return cast(list[_Record], records)
    raise _generation_stage_error(
        ErrorCode.CONTRACT,
        stage,
        "generation artifact failed validation",
    )


def _write_generation_records(
    path: Path,
    records: list[object],
    *,
    stage: str,
) -> None:
    try:
        write_jsonl(path, records, stage=stage)
    except (OSError, SecAwareError, UnicodeError):
        pass
    else:
        return
    raise _generation_stage_error(
        ErrorCode.CONTRACT,
        stage,
        "generation artifact could not be published",
    )


def _read_verified_generation_records(
    store: RunStore,
    path: Path,
    model: type[_Record],
    expected: list[_Record],
    outputs: list[Path],
    *,
    stage: str,
    max_records: int,
    mismatch_message: str,
) -> list[_Record]:
    readback_error: SecAwareError | None = None
    try:
        validated = _read_generation_records(
            path,
            model,
            stage=stage,
            allow_empty=False,
            max_records=max_records,
        )
    except SecAwareError as error:
        readback_error = error
    if readback_error is not None:
        store.verify_sealed_outputs(stage, outputs)
        raise readback_error from None
    if validated != expected:
        store.verify_sealed_outputs(stage, outputs)
        raise _generation_stage_error(
            ErrorCode.CONTRACT,
            stage,
            mismatch_message,
        )
    return validated


def _generation_stage_should_skip(
    store: RunStore,
    stage: str,
    inputs: list[Path],
    outputs: list[Path],
    *,
    force: bool,
) -> bool:
    try:
        return store.should_skip_stage(stage, inputs, outputs, force)
    except SecAwareError as error:
        code = error.code
        retryable = error.retryable
    if store.stage_is_active(stage):
        raise _generation_stage_error(
            code,
            stage,
            "generation stage execution is already active",
            retryable=retryable,
        )
    try:
        store.invalidate_stage(stage)
    except SecAwareError as error:
        code = error.code
        retryable = error.retryable
    raise _generation_stage_error(
        code,
        stage,
        "generation stage inputs could not be verified",
        retryable=retryable,
    )


def _invalidate_alternate_generation_stage(
    store: RunStore,
    *,
    stage: str,
    alternate_stage: str,
) -> None:
    try:
        store.invalidate_stage(alternate_stage)
    except SecAwareError as error:
        code = error.code
        retryable = error.retryable
    else:
        return
    try:
        store.invalidate_stage(stage)
    except SecAwareError as error:
        code = error.code
        retryable = error.retryable
    raise _generation_stage_error(
        code,
        stage,
        "generation stage manifest could not be invalidated",
        retryable=retryable,
    )


def _validate_offline_results_path(
    store: RunStore,
    *,
    stage: str,
    condition: GenerationCondition,
    results: Path,
) -> None:
    protected = [
        store.path("generation", f"{condition}_requests.jsonl"),
        store.path("generation", f"{condition}_code.jsonl"),
        store.path(".stages", f"plan-generation-{condition}.json"),
        store.path(".stages", f"import-generation-{condition}.json"),
        store.path(".stages", f"generate-{condition}.json"),
        store.path("config.resolved.yaml"),
        store.path("inputs", "prompts.jsonl"),
        store.path("interventions", "interventions.jsonl"),
        Path(store.config.data.prompts_path),
    ]
    invalid = False
    try:
        resolved_results = results.resolve()
        for protected_path in protected:
            if resolved_results == protected_path.resolve():
                invalid = True
                break
            if results.exists() and protected_path.exists() and os.path.samefile(
                results,
                protected_path,
            ):
                invalid = True
                break
    except (OSError, TypeError, ValueError):
        invalid = True
    if invalid:
        raise _generation_stage_error(
            ErrorCode.CONTRACT,
            stage,
            "offline generation results path conflicts with run artifacts",
        )


def _execute_generation_stage(
    store: RunStore,
    stage: str,
    action: Callable[[], _ActionResult],
) -> _ActionResult:
    failure: Exception
    try:
        return action()
    except Exception as error:
        failure = error
    try:
        store.invalidate_stage(stage)
    except SecAwareError as error:
        code = error.code
        retryable = error.retryable
    else:
        raise failure from None
    raise _generation_stage_error(
        code,
        stage,
        "failed generation stage could not be invalidated",
        retryable=retryable,
    )


def _require_committed_generation_plan(
    store: RunStore,
    *,
    condition: GenerationCondition,
    import_stage: str,
    legacy_stage: str,
    ledger: Path,
) -> None:
    plan_stage = f"plan-generation-{condition}"
    plan_inputs = [store.path("inputs", "prompts.jsonl")]
    if condition == "counterfactual":
        plan_inputs.append(store.path("interventions", "interventions.jsonl"))
    try:
        store.require_committed_stage(plan_stage, plan_inputs, [ledger])
    except SecAwareError:
        pass
    else:
        return
    cleanup_failed = False
    for stage in (import_stage, legacy_stage):
        try:
            store.invalidate_stage(stage)
        except SecAwareError:
            cleanup_failed = True
    message = (
        "generation producer trust failure could not be cleaned up"
        if cleanup_failed
        else "generation request ledger is not committed"
    )
    raise _generation_stage_error(
        ErrorCode.MANIFEST_CONFLICT,
        import_stage,
        message,
    )


def _require_committed_generation_code(
    store: RunStore,
    *,
    condition: str,
    consumer_stage: str,
    code_output: Path,
) -> None:
    for producer_stage in (
        f"import-generation-{condition}",
        f"generate-{condition}",
    ):
        try:
            store.require_committed_output(producer_stage, [code_output])
        except SecAwareError:
            continue
        return
    try:
        store.invalidate_stage(consumer_stage)
    except SecAwareError:
        pass
    raise _generation_stage_error(
        ErrorCode.MANIFEST_CONFLICT,
        consumer_stage,
        "generation code does not have a committed producer",
    )


def plan_generation_stage(
    config: AppConfig,
    store: RunStore,
    *,
    condition: GenerationCondition,
    force: bool,
) -> None:
    condition = _generation_condition(condition)
    stage = f"plan-generation-{condition}"
    prompts_path = store.path("inputs", "prompts.jsonl")
    inputs = [prompts_path]
    if condition == "counterfactual":
        inputs.append(store.path("interventions", "interventions.jsonl"))
    output = store.path("generation", f"{condition}_requests.jsonl")
    outputs = [output]
    if _generation_stage_should_skip(store, stage, inputs, outputs, force=force):
        return

    def execute() -> None:
        prompts = _read_generation_records(
            prompts_path,
            PromptRecord,
            stage=stage,
            allow_empty=False,
            max_records=MAX_GENERATION_AXIS_ITEMS,
        )
        if condition == "observed":
            records = plan_observed_requests(
                prompts,
                config.generation.models,
                config.generation.seeds,
                endpoint_type="offline",
            )
        else:
            interventions = _read_generation_records(
                inputs[1],
                InterventionRecord,
                stage=stage,
                allow_empty=False,
                max_records=MAX_GENERATION_AXIS_ITEMS,
            )
            records = plan_counterfactual_requests(
                {prompt.prompt_id: prompt for prompt in prompts},
                interventions,
                config.generation.models,
                config.generation.seeds,
                endpoint_type="offline",
            )
        _write_generation_records(output, cast(list[object], records), stage=stage)
        store.seal_stage_outputs(stage, outputs)
        _read_verified_generation_records(
            store,
            output,
            GenerationRequestRecord,
            records,
            outputs,
            stage=stage,
            max_records=MAX_GENERATION_REQUESTS,
            mismatch_message="generation request ledger changed during publication",
        )
        store.record_stage(stage, inputs, outputs)

    _execute_generation_stage(store, stage, execute)


def import_generation_stage(
    config: AppConfig,
    store: RunStore,
    *,
    condition: GenerationCondition,
    results_path: Path,
    force: bool,
) -> None:
    del config
    condition = _generation_condition(condition)
    stage = f"import-generation-{condition}"
    legacy_stage = f"generate-{condition}"
    ledger = store.path("generation", f"{condition}_requests.jsonl")
    output = store.path("generation", f"{condition}_code.jsonl")
    outputs = [output]
    results = Path(results_path)

    _validate_offline_results_path(
        store,
        stage=stage,
        condition=condition,
        results=results,
    )

    if not results.is_file():
        store.invalidate_stage(stage)
        store.invalidate_stage(legacy_stage)
        raise _generation_stage_error(
            ErrorCode.EXTERNAL_INPUT_REQUIRED,
            stage,
            "offline generation results are required",
            retryable=True,
        )

    _require_committed_generation_plan(
        store,
        condition=condition,
        import_stage=stage,
        legacy_stage=legacy_stage,
        ledger=ledger,
    )
    _invalidate_alternate_generation_stage(
        store,
        stage=stage,
        alternate_stage=legacy_stage,
    )
    inputs = [ledger, results]
    if _generation_stage_should_skip(store, stage, inputs, outputs, force=force):
        return

    def execute() -> None:
        expected = _read_generation_records(
            ledger,
            GenerationRequestRecord,
            stage=stage,
            allow_empty=False,
            max_records=MAX_OFFLINE_IMPORT_RECORDS,
        )
        received = _read_generation_records(
            results,
            OfflineGenerationResultRecord,
            stage=stage,
            allow_empty=True,
            max_records=MAX_OFFLINE_IMPORT_RECORDS,
        )
        imported = import_offline_results(expected, received)
        _write_generation_records(output, cast(list[object], imported), stage=stage)
        store.seal_stage_outputs(stage, outputs)
        _read_verified_generation_records(
            store,
            output,
            CanonicalGeneratedCodeRecord,
            imported,
            outputs,
            stage=stage,
            max_records=MAX_OFFLINE_IMPORT_RECORDS,
            mismatch_message="canonical generation output changed during publication",
        )
        store.record_stage(stage, inputs, outputs)

    _execute_generation_stage(store, stage, execute)


def extract_prompt_tsg_stage(config: AppConfig, store: RunStore, *, force: bool) -> None:
    del config
    stage = "extract-prompt-tsg"
    inputs = [store.path("inputs", "prompts.jsonl")]
    output = store.path("tsg", "prompt_tsg.jsonl")
    outputs = [output]
    if store.should_skip_stage(stage, inputs, outputs, force):
        return
    prompts = _prompt_records(store)
    write_jsonl(output, [extract_prompt_tsg(prompt) for prompt in prompts])
    store.record_stage(stage, inputs, outputs)


def generate_observed_stage(config: AppConfig, store: RunStore, *, force: bool) -> None:
    stage = "generate-observed"
    inputs = [store.path("inputs", "prompts.jsonl")]
    if config.generation.provider == "file" and config.generation.file_provider_dir is not None:
        inputs.append(Path(config.generation.file_provider_dir))
    output = store.path("generation", "observed_code.jsonl")
    outputs = [output]
    if store.should_skip_stage(stage, inputs, outputs, force):
        return
    prompts = _prompt_records(store)
    provider = get_provider(
        config.generation.provider,
        file_provider_dir=config.generation.file_provider_dir,
    )
    records: list[GeneratedCodeRecord] = []
    for prompt in prompts:
        for model_id in config.generation.models:
            for seed in config.generation.seeds:
                code_id = f"observed_{prompt.prompt_id}_{_safe_id(model_id)}_{seed}"
                records.append(
                    GeneratedCodeRecord(
                        code_id=code_id,
                        prompt_id=prompt.prompt_id,
                        condition="observed",
                        model_id=model_id,
                        seed_id=seed,
                        code=provider.generate(
                            prompt.prompt,
                            model_id=model_id,
                            seed=seed,
                            language=prompt.language,
                        ),
                    )
                )
    write_jsonl(output, records)
    store.record_stage(stage, inputs, outputs)


def extract_code_tsg_stage(
    config: AppConfig,
    store: RunStore,
    *,
    condition: str,
    force: bool,
) -> None:
    del config
    stage = f"extract-code-tsg-{condition}"
    source_name = "observed_code.jsonl" if condition == "observed" else "counterfactual_code.jsonl"
    output_name = "observed_code_tsg.jsonl" if condition == "observed" else "counterfactual_code_tsg.jsonl"
    inputs = [store.path("generation", source_name)]
    output = store.path("tsg", output_name)
    outputs = [output]
    _require_committed_generation_code(
        store,
        condition=condition,
        consumer_stage=stage,
        code_output=inputs[0],
    )
    if store.should_skip_stage(stage, inputs, outputs, force):
        return
    codes = read_jsonl(inputs[0], GeneratedCodeRecord)
    write_jsonl(output, [extract_code_tsg(code) for code in codes])  # type: ignore[arg-type]
    store.record_stage(stage, inputs, outputs)


def run_oracle_stage(
    config: AppConfig,
    store: RunStore,
    *,
    condition: str,
    force: bool,
) -> None:
    if not config.oracle.use_lightweight_rules:
        raise typer.BadParameter("The engineering v0 requires oracle.use_lightweight_rules=true.")
    stage = f"run-oracle-{condition}"
    source_name = "observed_code.jsonl" if condition == "observed" else "counterfactual_code.jsonl"
    output_name = "observed_oracle.jsonl" if condition == "observed" else "counterfactual_oracle.jsonl"
    inputs = [store.path("generation", source_name)]
    output = store.path("oracle", output_name)
    outputs = [output]
    _require_committed_generation_code(
        store,
        condition=condition,
        consumer_stage=stage,
        code_output=inputs[0],
    )
    if store.should_skip_stage(stage, inputs, outputs, force):
        return
    codes = read_jsonl(inputs[0], GeneratedCodeRecord)
    write_jsonl(output, [run_code_oracle(code) for code in codes])  # type: ignore[arg-type]
    store.record_stage(stage, inputs, outputs)


def discover_stage(config: AppConfig, store: RunStore, *, force: bool) -> None:
    stage = "discover"
    inputs = [
        store.path("inputs", "prompts.jsonl"),
        store.path("tsg", "prompt_tsg.jsonl"),
        store.path("tsg", "observed_code_tsg.jsonl"),
        store.path("oracle", "observed_oracle.jsonl"),
    ]
    all_output = store.path("discovery", "hypotheses_all.jsonl")
    selected_output = store.path("discovery", "hypotheses_selected.jsonl")
    outputs = [all_output, selected_output]
    if store.should_skip_stage(stage, inputs, outputs, force):
        return
    prompts = [prompt for prompt in _prompt_records(store) if prompt.split == "discover"]
    prompt_tsgs = [
        tsg
        for tsg in read_jsonl(store.path("tsg", "prompt_tsg.jsonl"), TSGRecord)  # type: ignore[arg-type]
        if tsg.prompt_id in {prompt.prompt_id for prompt in prompts}
    ]
    code_tsgs = [
        tsg
        for tsg in read_jsonl(store.path("tsg", "observed_code_tsg.jsonl"), TSGRecord)  # type: ignore[arg-type]
        if tsg.prompt_id in {prompt.prompt_id for prompt in prompts}
    ]
    oracles = [
        record
        for record in read_jsonl(store.path("oracle", "observed_oracle.jsonl"), OracleRecord)  # type: ignore[arg-type]
        if record.prompt_id in {prompt.prompt_id for prompt in prompts}
    ]
    all_h, selected_h = discover_hypotheses(
        prompts,
        prompt_tsgs,
        code_tsgs,
        oracles,
        min_support_total=config.discovery.min_support_total,
        min_support_each_side=config.discovery.min_support_each_side,
        top_k_per_scope=config.discovery.top_k_per_scope,
        score_weights=config.discovery.score_weights,
    )
    selected_h = selected_h[: config.intervention.max_hypotheses]
    write_jsonl(all_output, all_h)
    write_jsonl(selected_output, selected_h)
    store.record_stage(stage, inputs, outputs)


def intervene_stage(config: AppConfig, store: RunStore, *, force: bool) -> None:
    stage = "intervene"
    inputs = [
        store.path("inputs", "prompts.jsonl"),
        store.path("tsg", "prompt_tsg.jsonl"),
        store.path("discovery", "hypotheses_selected.jsonl"),
    ]
    output = store.path("interventions", "interventions.jsonl")
    paired_output = store.path("interventions", "paired_prompts.jsonl")
    outputs = [output, paired_output]
    if store.should_skip_stage(stage, inputs, outputs, force):
        return
    prompts = [prompt for prompt in _prompt_records(store) if prompt.split == "confirm"]
    prompt_by_id = {prompt.prompt_id: prompt for prompt in prompts}
    prompt_tsgs = {
        tsg.prompt_id: tsg
        for tsg in read_jsonl(store.path("tsg", "prompt_tsg.jsonl"), TSGRecord)  # type: ignore[arg-type]
        if tsg.prompt_id in prompt_by_id
    }
    hypotheses = read_jsonl(
        store.path("discovery", "hypotheses_selected.jsonl"), HypothesisRecord
    )
    interventions: list[InterventionRecord] = []
    for hypothesis in hypotheses:  # type: ignore[assignment]
        if "risk_down" not in config.intervention.enabled_directions:
            continue
        for prompt in prompts:
            if not _matches_scope(prompt, hypothesis):
                continue
            interventions.append(apply_intervention(prompt, prompt_tsgs[prompt.prompt_id], hypothesis))
    write_jsonl(output, interventions)
    write_jsonl(
        paired_output,
        [
            {
                "intervention_id": item.intervention_id,
                "prompt_id": item.prompt_id,
                "hypothesis_id": item.hypothesis_id,
                "original_prompt": item.original_prompt,
                "counterfactual_prompt": item.counterfactual_prompt,
            }
            for item in interventions
        ],
    )
    store.record_stage(stage, inputs, outputs)


def generate_counterfactual_stage(config: AppConfig, store: RunStore, *, force: bool) -> None:
    stage = "generate-counterfactual"
    inputs = [
        store.path("inputs", "prompts.jsonl"),
        store.path("interventions", "interventions.jsonl"),
    ]
    if config.generation.provider == "file" and config.generation.file_provider_dir is not None:
        inputs.append(Path(config.generation.file_provider_dir))
    output = store.path("generation", "counterfactual_code.jsonl")
    outputs = [output]
    if store.should_skip_stage(stage, inputs, outputs, force):
        return
    prompts = {prompt.prompt_id: prompt for prompt in _prompt_records(store)}
    interventions = read_jsonl(
        store.path("interventions", "interventions.jsonl"), InterventionRecord
    )
    provider = get_provider(
        config.generation.provider,
        file_provider_dir=config.generation.file_provider_dir,
    )
    records: list[GeneratedCodeRecord] = []
    for intervention in interventions:  # type: ignore[assignment]
        prompt = prompts[intervention.prompt_id]
        for model_id in config.generation.models:
            for seed in config.generation.seeds:
                code_id = (
                    f"counterfactual_{intervention.prompt_id}_{intervention.hypothesis_id}_"
                    f"{_safe_id(model_id)}_{seed}"
                )
                records.append(
                    GeneratedCodeRecord(
                        code_id=code_id,
                        prompt_id=intervention.prompt_id,
                        condition="counterfactual",
                        model_id=model_id,
                        seed_id=seed,
                        hypothesis_id=intervention.hypothesis_id,
                        intervention_id=intervention.intervention_id,
                        code=provider.generate(
                            intervention.counterfactual_prompt,
                            model_id=model_id,
                            seed=seed,
                            language=prompt.language,
                        ),
                    )
                )
    write_jsonl(output, records)
    store.record_stage(stage, inputs, outputs)


def confirm_stage(config: AppConfig, store: RunStore, *, force: bool) -> None:
    stage = "confirm"
    inputs = [
        store.path("interventions", "interventions.jsonl"),
        store.path("oracle", "observed_oracle.jsonl"),
        store.path("oracle", "counterfactual_oracle.jsonl"),
        store.path("discovery", "hypotheses_selected.jsonl"),
    ]
    pair_output = store.path("analysis", "pair_results.jsonl")
    effect_output = store.path("analysis", "hypothesis_effects.jsonl")
    outputs = [pair_output, effect_output]
    if store.should_skip_stage(stage, inputs, outputs, force):
        return
    interventions = read_jsonl(
        store.path("interventions", "interventions.jsonl"), InterventionRecord
    )
    observed = read_jsonl(store.path("oracle", "observed_oracle.jsonl"), OracleRecord)
    counterfactual = read_jsonl(store.path("oracle", "counterfactual_oracle.jsonl"), OracleRecord)
    pairs = build_pairs(interventions, observed, counterfactual)  # type: ignore[arg-type]
    effects = estimate_effects(
        pairs,
        bootstrap_samples=config.analysis.bootstrap_samples,
        ci_level=config.analysis.ci_level,
        min_eligible_pairs=config.analysis.min_eligible_pairs,
        min_flip_rate=config.analysis.min_flip_rate,
        max_side_effect_rate_confirmed=config.analysis.max_side_effect_rate_confirmed,
        random_seed=config.run.random_seed,
    )
    hypotheses = {
        hypothesis.hypothesis_id: hypothesis
        for hypothesis in read_jsonl(
            store.path("discovery", "hypotheses_selected.jsonl"), HypothesisRecord
        )
    }
    for effect in effects:
        hypothesis = hypotheses.get(effect.hypothesis_id)
        if hypothesis:
            effect.scope_cwe = hypothesis.scope.get("cwe", "")
            effect.scope_task_family = hypothesis.scope.get("task_family", "")
    write_jsonl(pair_output, pairs)
    write_jsonl(effect_output, effects)
    store.record_stage(stage, inputs, outputs)


def report_stage(config: AppConfig, store: RunStore, *, force: bool) -> None:
    del config
    stage = "report"
    inputs = [
        store.path("inputs", "prompts.jsonl"),
        store.path("discovery", "hypotheses_all.jsonl"),
        store.path("discovery", "hypotheses_selected.jsonl"),
        store.path("interventions", "interventions.jsonl"),
        store.path("analysis", "pair_results.jsonl"),
        store.path("analysis", "hypothesis_effects.jsonl"),
    ]
    outputs = [
        store.path("reports", "funnel.csv"),
        store.path("reports", "effects.csv"),
        store.path("reports", "failures.csv"),
        store.path("reports", "mechanism_cards.jsonl"),
        store.path("reports", "summary.md"),
    ]
    if store.should_skip_stage(stage, inputs, outputs, force):
        return
    write_reports(
        store.path("reports"),
        prompts=_prompt_records(store),
        hypotheses_all=read_jsonl(
            store.path("discovery", "hypotheses_all.jsonl"), HypothesisRecord
        ),  # type: ignore[arg-type]
        hypotheses_selected=read_jsonl(
            store.path("discovery", "hypotheses_selected.jsonl"), HypothesisRecord
        ),  # type: ignore[arg-type]
        interventions=read_jsonl(
            store.path("interventions", "interventions.jsonl"), InterventionRecord
        ),  # type: ignore[arg-type]
        pairs=read_jsonl(store.path("analysis", "pair_results.jsonl"), PairResult),  # type: ignore[arg-type]
        effects=read_jsonl(
            store.path("analysis", "hypothesis_effects.jsonl"), EffectRecord
        ),  # type: ignore[arg-type]
    )
    store.record_stage(stage, inputs, outputs)


def _matches_scope(prompt: PromptRecord, hypothesis: HypothesisRecord) -> bool:
    task_family = hypothesis.scope.get("task_family")
    cwe = hypothesis.scope.get("cwe")
    return (not task_family or prompt.task_family == task_family) and (not cwe or prompt.cwe == cwe)


def _safe_id(value: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in value)


@app.callback()
def main() -> None:
    """Run SecAware pipeline stages."""


@app.command("preflight")
@cli_action
def preflight_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
) -> None:
    cfg, _store = _load(config, run_dir)
    report = run_preflight(cfg)
    typer.echo(
        "Preflight OK: "
        f"prompts={report.prompt_count} "
        f"discover={report.discover_count} "
        f"confirm={report.confirm_count} "
        f"models={report.model_count} "
        f"seeds={report.seed_count} "
        f"output_dir={report.output_dir}"
    )


@app.command("extract-prompt-tsg")
@cli_action
def extract_prompt_tsg_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    cfg, store = _load(config, run_dir)
    _prepare(cfg, store)
    extract_prompt_tsg_stage(cfg, store, force=force)


@app.command("generate-observed")
@cli_action
def generate_observed_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    cfg, store = _load(config, run_dir)
    _prepare(cfg, store)
    generate_observed_stage(cfg, store, force=force)


@app.command("plan-generation")
@cli_action
def plan_generation_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    condition: str = typer.Option("observed", "--condition"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    validated_condition = _generation_condition(condition)
    cfg, store = _load(config, run_dir)
    _prepare(cfg, store)
    plan_generation_stage(
        cfg,
        store,
        condition=validated_condition,
        force=force,
    )


@app.command("import-generation")
@cli_action
def import_generation_command(
    config: Path = typer.Option(..., "--config"),
    results: Path = typer.Option(..., "--results"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    condition: str = typer.Option("observed", "--condition"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    validated_condition = _generation_condition(condition)
    cfg, store = _load(config, run_dir)
    import_generation_stage(
        cfg,
        store,
        condition=validated_condition,
        results_path=results,
        force=force,
    )


@app.command("extract-code-tsg")
@cli_action
def extract_code_tsg_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    condition: str = typer.Option("observed", "--condition"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    cfg, store = _load(config, run_dir)
    extract_code_tsg_stage(cfg, store, condition=condition, force=force)


@app.command("run-oracle")
@cli_action
def run_oracle_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    condition: str = typer.Option("observed", "--condition"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    cfg, store = _load(config, run_dir)
    run_oracle_stage(cfg, store, condition=condition, force=force)


@app.command("discover")
@cli_action
def discover_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    cfg, store = _load(config, run_dir)
    discover_stage(cfg, store, force=force)


@app.command("intervene")
@cli_action
def intervene_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    cfg, store = _load(config, run_dir)
    intervene_stage(cfg, store, force=force)


@app.command("generate-counterfactual")
@cli_action
def generate_counterfactual_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    cfg, store = _load(config, run_dir)
    generate_counterfactual_stage(cfg, store, force=force)


@app.command("confirm")
@cli_action
def confirm_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    cfg, store = _load(config, run_dir)
    confirm_stage(cfg, store, force=force)


@app.command("report")
@cli_action
def report_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    cfg, store = _load(config, run_dir)
    report_stage(cfg, store, force=force)


@app.command("run-all")
@cli_action
def run_all_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    cfg, store = _load(config, run_dir)
    _prepare(cfg, store)
    extract_prompt_tsg_stage(cfg, store, force=force)
    generate_observed_stage(cfg, store, force=force)
    extract_code_tsg_stage(cfg, store, condition="observed", force=force)
    run_oracle_stage(cfg, store, condition="observed", force=force)
    discover_stage(cfg, store, force=force)
    intervene_stage(cfg, store, force=force)
    generate_counterfactual_stage(cfg, store, force=force)
    extract_code_tsg_stage(cfg, store, condition="counterfactual", force=force)
    run_oracle_stage(cfg, store, condition="counterfactual", force=force)
    confirm_stage(cfg, store, force=force)
    report_stage(cfg, store, force=force)
    console.print(f"SecAware run complete: {store.root}")


if __name__ == "__main__":
    app()

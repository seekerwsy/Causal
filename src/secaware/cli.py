from pathlib import Path
from typing import Optional

import typer

from secaware.analysis.effects import estimate_effects
from secaware.analysis.pairing import build_pairs
from secaware.commands.common import run_cli_action
from secaware.config import AppConfig, load_config
from secaware.discovery.tsg_qcd import discover_hypotheses
from secaware.extractors.code_tsg_extractor import extract_code_tsg
from secaware.extractors.prompt_tsg_extractor import extract_prompt_tsg
from secaware.generation.providers import get_provider
from secaware.intervention.operators import apply_intervention
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.io.run_store import RunStore
from secaware.logging_utils import console
from secaware.oracle.aggregator import run_oracle as run_code_oracle
from secaware.pipeline.preflight import run_preflight
from secaware.reports.tables import write_reports
from secaware.schema.hypotheses import HypothesisRecord
from secaware.schema.interventions import InterventionRecord
from secaware.schema.records import GeneratedCodeRecord, PromptRecord
from secaware.schema.results import EffectRecord, OracleRecord, PairResult
from secaware.schema.tsg import TSGRecord

app = typer.Typer(help="SecAware reproducible prompt-side security mechanism pipeline.")


def _load(config: Path, run_dir: Optional[Path]) -> tuple[AppConfig, RunStore]:
    loaded = load_config(config, run_dir=run_dir)
    return loaded, RunStore(loaded)


def _prepare(config: AppConfig, store: RunStore) -> None:
    del config
    store.prepare()


def _prompt_records(store: RunStore) -> list[PromptRecord]:
    return read_jsonl(store.path("inputs", "prompts.jsonl"), PromptRecord)  # type: ignore[return-value]


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
def preflight_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
) -> None:
    def action() -> None:
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

    run_cli_action(action)


@app.command("extract-prompt-tsg")
def extract_prompt_tsg_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    cfg, store = _load(config, run_dir)
    _prepare(cfg, store)
    extract_prompt_tsg_stage(cfg, store, force=force)


@app.command("generate-observed")
def generate_observed_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    cfg, store = _load(config, run_dir)
    _prepare(cfg, store)
    generate_observed_stage(cfg, store, force=force)


@app.command("extract-code-tsg")
def extract_code_tsg_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    condition: str = typer.Option("observed", "--condition"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    cfg, store = _load(config, run_dir)
    extract_code_tsg_stage(cfg, store, condition=condition, force=force)


@app.command("run-oracle")
def run_oracle_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    condition: str = typer.Option("observed", "--condition"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    cfg, store = _load(config, run_dir)
    run_oracle_stage(cfg, store, condition=condition, force=force)


@app.command("discover")
def discover_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    cfg, store = _load(config, run_dir)
    discover_stage(cfg, store, force=force)


@app.command("intervene")
def intervene_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    cfg, store = _load(config, run_dir)
    intervene_stage(cfg, store, force=force)


@app.command("generate-counterfactual")
def generate_counterfactual_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    cfg, store = _load(config, run_dir)
    generate_counterfactual_stage(cfg, store, force=force)


@app.command("confirm")
def confirm_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    cfg, store = _load(config, run_dir)
    confirm_stage(cfg, store, force=force)


@app.command("report")
def report_command(
    config: Path = typer.Option(..., "--config"),
    run_dir: Optional[Path] = typer.Option(None, "--run-dir"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    cfg, store = _load(config, run_dir)
    report_stage(cfg, store, force=force)


@app.command("run-all")
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

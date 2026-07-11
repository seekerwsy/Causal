from collections import defaultdict

from secaware.discovery.candidate_enum import FACTOR_SPECS, FactorSpec
from secaware.discovery.scoring import (
    association_score,
    nuisance_penalty,
    path_score,
    stability_score,
)
from secaware.schema.hypotheses import HypothesisRecord
from secaware.schema.records import PromptRecord
from secaware.schema.results import LegacyOracleRecord
from secaware.schema.tsg import TSGRecord


DEFAULT_WEIGHTS = {
    "association": 0.35,
    "path": 0.35,
    "targetability": 0.15,
    "stability": 0.15,
    "nuisance_penalty": 0.20,
}


def _oracle_by_prompt(
    records: list[LegacyOracleRecord],
) -> dict[str, list[LegacyOracleRecord]]:
    grouped: dict[str, list[LegacyOracleRecord]] = defaultdict(list)
    for record in records:
        if record.prompt_id:
            grouped[record.prompt_id].append(record)
    return grouped


def _tsg_by_prompt(records: list[TSGRecord]) -> dict[str, list[TSGRecord]]:
    grouped: dict[str, list[TSGRecord]] = defaultdict(list)
    for record in records:
        grouped[record.prompt_id].append(record)
    return grouped


def _scope_prompts(prompts: list[PromptRecord], spec: FactorSpec) -> list[PromptRecord]:
    scoped = [prompt for prompt in prompts if prompt.task_family == spec.task_family or prompt.cwe == spec.cwe]
    return scoped or prompts


def discover_hypotheses(
    prompts: list[PromptRecord],
    prompt_tsgs: list[TSGRecord],
    code_tsgs: list[TSGRecord],
    oracle_records: list[LegacyOracleRecord],
    *,
    min_support_total: int = 4,
    min_support_each_side: int = 1,
    top_k_per_scope: int = 2,
    score_weights: dict[str, float] | None = None,
) -> tuple[list[HypothesisRecord], list[HypothesisRecord]]:
    weights = {**DEFAULT_WEIGHTS, **(score_weights or {})}
    prompt_tsg_by_id = {tsg.prompt_id: tsg for tsg in prompt_tsgs}
    oracle_by_prompt = _oracle_by_prompt(oracle_records)
    code_tsg_by_prompt = _tsg_by_prompt(code_tsgs)
    all_hypotheses: list[HypothesisRecord] = []

    for index, spec in enumerate(FACTOR_SPECS.values(), start=1):
        scoped_prompts = _scope_prompts(prompts, spec)
        scoped_tsgs = [prompt_tsg_by_id[p.prompt_id] for p in scoped_prompts if p.prompt_id in prompt_tsg_by_id]
        if not scoped_tsgs:
            continue
        assoc, raw, support = association_score(spec, scoped_tsgs, oracle_by_prompt)
        if support["n_total"] < min_support_total:
            global_tsgs = [prompt_tsg_by_id[p.prompt_id] for p in prompts if p.prompt_id in prompt_tsg_by_id]
            assoc, raw, support = association_score(spec, global_tsgs, oracle_by_prompt)
            scoring_tsgs = global_tsgs
        else:
            scoring_tsgs = scoped_tsgs
        if support["n_total"] < min_support_total:
            continue
        if support["n_present"] < min_support_each_side or support["n_absent"] < min_support_each_side:
            continue
        path = path_score(spec, scoring_tsgs, code_tsg_by_prompt, oracle_by_prompt)
        targetability = 1.0
        stability = stability_score(spec, prompts, prompt_tsg_by_id, oracle_by_prompt)
        penalty = nuisance_penalty(spec, prompts, prompt_tsg_by_id)
        score = (
            weights["association"] * assoc
            + weights["path"] * path
            + weights["targetability"] * targetability
            + weights["stability"] * stability
            - weights["nuisance_penalty"] * penalty
        )
        hypothesis_id = f"h_{spec.cwe.replace('-', '')}_{spec.factor_type.value}_{index:03}"
        all_hypotheses.append(
            HypothesisRecord(
                hypothesis_id=hypothesis_id,
                factor_type=spec.factor_type,
                prompt_factor=spec.prompt_factor,
                mechanism_motif=spec.prompt_motif,
                expected_direction="risk_down_when_added",
                scope={
                    "language": "python",
                    "cwe": spec.cwe,
                    "task_family": spec.task_family,
                },
                patch_operator=spec.patch_operator,
                discovery_score=round(max(0.0, score), 6),
                association_score=round(assoc, 6),
                path_score=round(path, 6),
                targetability_score=targetability,
                stability_score=round(stability, 6),
                nuisance_penalty=round(penalty, 6),
                support={**support, "association_raw": round(raw, 6)},
                status="candidate",
            )
        )

    all_hypotheses.sort(key=lambda record: record.discovery_score, reverse=True)
    selected_by_scope: dict[tuple[str, str], list[HypothesisRecord]] = defaultdict(list)
    selected: list[HypothesisRecord] = []
    for hypothesis in all_hypotheses:
        key = (hypothesis.scope.get("cwe", ""), hypothesis.scope.get("task_family", ""))
        if len(selected_by_scope[key]) >= top_k_per_scope:
            continue
        hypothesis.status = "selected_for_confirmation"
        selected_by_scope[key].append(hypothesis)
        selected.append(hypothesis)
    for hypothesis in all_hypotheses:
        if hypothesis not in selected:
            hypothesis.status = "not_selected"
    return all_hypotheses, selected

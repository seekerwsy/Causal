from __future__ import annotations

from collections import defaultdict

from secaware.discovery.candidate_enum import FACTOR_SPECS, FactorSpec
from secaware.discovery.scoring import (
    _evaluate_prompt_tsgs,
    _revalidate_oracle,
    association_score,
    graph_evidence_summary,
    nuisance_penalty,
    path_score,
    stability_score,
)
from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.hypotheses import HypothesisRecord
from secaware.schema.oracle import OracleRecord
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import PromptTSGRecord


DEFAULT_WEIGHTS = {
    "association": 0.35,
    "path": 0.35,
    "targetability": 0.15,
    "stability": 0.15,
    "nuisance_penalty": 0.20,
}


def _coordinate_error() -> SecAwareError:
    return SecAwareError(
        ErrorCode.ANALYSIS_INVALID,
        "discovery.coordinates",
        "discovery prompt graph coordinates are invalid",
    )


def _oracle_by_prompt(records: list[OracleRecord]) -> dict[str, list[OracleRecord]]:
    grouped: dict[str, list[OracleRecord]] = defaultdict(list)
    for record in records:
        validated = _revalidate_oracle(record)
        grouped[validated.prompt_id].append(validated)
    return grouped


def _scope_prompts(prompts: list[PromptRecord], spec: FactorSpec) -> list[PromptRecord]:
    scoped = [
        prompt
        for prompt in prompts
        if prompt.task_family == spec.task_family or prompt.cwe == spec.cwe
    ]
    return scoped or prompts


def _validated_coordinates(
    prompts: list[PromptRecord],
    prompt_tsgs: list[PromptTSGRecord],
) -> tuple[list[PromptRecord], dict[str, PromptTSGRecord]]:
    evaluated = _evaluate_prompt_tsgs(prompt_tsgs)
    prompt_ids = [prompt.prompt_id for prompt in prompts]
    if (
        any(not prompt_id or not prompt_id.strip() for prompt_id in prompt_ids)
        or len(set(prompt_ids)) != len(prompt_ids)
        or set(prompt_ids) != {item.prompt_id for item in evaluated}
    ):
        prompts = []
        prompt_tsgs = []
        raise _coordinate_error() from None
    ordered_prompts = sorted(prompts, key=lambda prompt: prompt.prompt_id)
    graph_by_id = {
        item.prompt_id: record for item, record in zip(evaluated, prompt_tsgs, strict=True)
    }
    return ordered_prompts, graph_by_id


def _discover_impl(
    prompts: list[PromptRecord],
    prompt_tsgs: list[PromptTSGRecord],
    oracle_records: list[OracleRecord],
    *,
    min_support_total: int,
    min_support_each_side: int,
    top_k_per_scope: int,
    score_weights: dict[str, float] | None,
) -> tuple[list[HypothesisRecord], list[HypothesisRecord]]:
    ordered_prompts, prompt_tsg_by_id = _validated_coordinates(prompts, prompt_tsgs)
    weights = {**DEFAULT_WEIGHTS, **(score_weights or {})}
    oracle_by_prompt = _oracle_by_prompt(oracle_records)
    global_tsgs = [prompt_tsg_by_id[prompt.prompt_id] for prompt in ordered_prompts]
    all_hypotheses: list[HypothesisRecord] = []

    for index, spec in enumerate(FACTOR_SPECS.values(), start=1):
        scoped_prompts = _scope_prompts(ordered_prompts, spec)
        scoped_tsgs = [prompt_tsg_by_id[prompt.prompt_id] for prompt in scoped_prompts]
        association, raw, support = association_score(spec, scoped_tsgs, oracle_by_prompt)
        scoring_tsgs = scoped_tsgs
        if support["n_total"] < min_support_total:
            association, raw, support = association_score(spec, global_tsgs, oracle_by_prompt)
            scoring_tsgs = global_tsgs
        if support["n_total"] < min_support_total:
            continue
        if (
            support["n_present"] < min_support_each_side
            or support["n_absent"] < min_support_each_side
        ):
            continue

        path = path_score(spec, scoring_tsgs, oracle_by_prompt)
        targetability = 1.0
        stability = stability_score(spec, ordered_prompts, prompt_tsg_by_id, oracle_by_prompt)
        penalty = nuisance_penalty(spec, ordered_prompts, prompt_tsg_by_id)
        score = (
            weights["association"] * association
            + weights["path"] * path
            + weights["targetability"] * targetability
            + weights["stability"] * stability
            - weights["nuisance_penalty"] * penalty
        )
        evidence = graph_evidence_summary(spec, scoring_tsgs)
        hypothesis_id = f"h_{spec.cwe.replace('-', '')}_{spec.factor_type.value}_{index:03}"
        all_hypotheses.append(
            HypothesisRecord(
                hypothesis_id=hypothesis_id,
                factor_type=spec.factor_type,
                motif_id=spec.motif_id,
                requirement_label=spec.requirement_label,
                guard_label=spec.guard_label,
                expected_direction="risk_down_when_added",
                scope={
                    "language": "python",
                    "cwe": spec.cwe,
                    "task_family": spec.task_family,
                },
                patch_operator=spec.patch_operator,
                discovery_score=round(max(0.0, score), 6),
                association_score=round(association, 6),
                path_score=round(path, 6),
                targetability_score=targetability,
                stability_score=round(stability, 6),
                nuisance_penalty=round(penalty, 6),
                support={**support, **evidence, "association_raw": round(raw, 6)},
                status="candidate",
            )
        )

    all_hypotheses.sort(key=lambda record: (-record.discovery_score, record.hypothesis_id))
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


def discover_hypotheses(
    prompts: list[PromptRecord],
    prompt_tsgs: list[PromptTSGRecord],
    oracle_records: list[OracleRecord],
    *,
    min_support_total: int = 4,
    min_support_each_side: int = 1,
    top_k_per_scope: int = 2,
    score_weights: dict[str, float] | None = None,
) -> tuple[list[HypothesisRecord], list[HypothesisRecord]]:
    try:
        return _discover_impl(
            prompts,
            prompt_tsgs,
            oracle_records,
            min_support_total=min_support_total,
            min_support_each_side=min_support_each_side,
            top_k_per_scope=top_k_per_scope,
            score_weights=score_weights,
        )
    except Exception as error:
        prompts = []
        prompt_tsgs = []
        oracle_records = []
        score_weights = None
        raise error.with_traceback(None) from None


__all__ = ["DEFAULT_WEIGHTS", "discover_hypotheses"]

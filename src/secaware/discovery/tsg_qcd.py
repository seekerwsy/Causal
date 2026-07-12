from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
import math
from types import MappingProxyType

from secaware.discovery.candidate_enum import FACTOR_SPECS, FactorSpec
from secaware.discovery.scoring import (
    EvaluatedPromptGraph,
    _association_from_evaluated,
    _evaluate_prompt_tsgs,
    _graph_evidence_from_evaluated,
    _nuisance_from_evaluated,
    _path_from_evaluated,
    _revalidate_oracle,
    _stability_from_evaluated,
)
from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.hypotheses import FactorType, HypothesisRecord
from secaware.schema.oracle import OracleRecord
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import MotifId, PromptTSGRecord


DEFAULT_WEIGHTS: Mapping[str, float] = MappingProxyType(
    {
        "association": 0.35,
        "path": 0.35,
        "targetability": 0.15,
        "stability": 0.15,
        "nuisance_penalty": 0.20,
    }
)
_PRIMARY_WEIGHT_KEYS = ("association", "path", "targetability", "stability")
_WEIGHT_KEYS = frozenset(DEFAULT_WEIGHTS)
_WEIGHT_SUM_TOLERANCE = 1e-12


def _coordinate_error() -> SecAwareError:
    return SecAwareError(
        ErrorCode.ANALYSIS_INVALID,
        "discovery.coordinates",
        "discovery prompt graph coordinates are invalid",
    )


def _configuration_error() -> SecAwareError:
    return SecAwareError(
        ErrorCode.ANALYSIS_INVALID,
        "discovery.configuration",
        "discovery scoring configuration is invalid",
    )


def _validated_configuration(
    *,
    score_weights: dict[str, float] | None,
    min_support_total: int,
    min_support_each_side: int,
    top_k_per_scope: int,
) -> Mapping[str, float]:
    if (
        type(min_support_total) is not int
        or min_support_total < 0
        or type(min_support_each_side) is not int
        or min_support_each_side < 0
        or type(top_k_per_scope) is not int
        or top_k_per_scope <= 0
        or (score_weights is not None and type(score_weights) is not dict)
    ):
        raise _configuration_error() from None
    overrides = score_weights or {}
    if not overrides.keys() <= _WEIGHT_KEYS:
        raise _configuration_error() from None
    weights = {**DEFAULT_WEIGHTS, **overrides}
    if any(
        type(value) not in {int, float} or not math.isfinite(value) or not 0.0 <= value <= 1.0
        for value in weights.values()
    ):
        raise _configuration_error() from None
    if not math.isclose(
        sum(weights[key] for key in _PRIMARY_WEIGHT_KEYS),
        1.0,
        rel_tol=0.0,
        abs_tol=_WEIGHT_SUM_TOLERANCE,
    ):
        raise _configuration_error() from None
    return MappingProxyType({key: float(weights[key]) for key in DEFAULT_WEIGHTS})


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
) -> tuple[
    list[PromptRecord],
    tuple[EvaluatedPromptGraph, ...],
    dict[str, EvaluatedPromptGraph],
]:
    evaluated = _evaluate_prompt_tsgs(
        prompt_tsgs,
        factor_types=tuple(FactorType),
        motif_ids=tuple(MotifId),
    )
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
    evaluated_by_id = {item.prompt_id: item for item in evaluated}
    ordered_evaluated = tuple(evaluated_by_id[prompt.prompt_id] for prompt in ordered_prompts)
    return ordered_prompts, ordered_evaluated, evaluated_by_id


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
    weights = _validated_configuration(
        score_weights=score_weights,
        min_support_total=min_support_total,
        min_support_each_side=min_support_each_side,
        top_k_per_scope=top_k_per_scope,
    )
    ordered_prompts, global_evaluated, evaluated_by_id = _validated_coordinates(
        prompts,
        prompt_tsgs,
    )
    oracle_by_prompt = _oracle_by_prompt(oracle_records)
    all_hypotheses: list[HypothesisRecord] = []

    for index, spec in enumerate(FACTOR_SPECS.values(), start=1):
        scoped_prompts = _scope_prompts(ordered_prompts, spec)
        scoped_evaluated = tuple(evaluated_by_id[prompt.prompt_id] for prompt in scoped_prompts)
        association, raw, support = _association_from_evaluated(
            spec,
            scoped_evaluated,
            oracle_by_prompt,
        )
        scoring_evaluated = scoped_evaluated
        if support["n_total"] < min_support_total:
            association, raw, support = _association_from_evaluated(
                spec,
                global_evaluated,
                oracle_by_prompt,
            )
            scoring_evaluated = global_evaluated
        if support["n_total"] < min_support_total:
            continue
        if (
            support["n_present"] < min_support_each_side
            or support["n_absent"] < min_support_each_side
        ):
            continue

        path = _path_from_evaluated(spec, scoring_evaluated, oracle_by_prompt)
        targetability = 1.0
        stability = _stability_from_evaluated(
            spec,
            ordered_prompts,
            evaluated_by_id,
            oracle_by_prompt,
        )
        penalty = _nuisance_from_evaluated(spec, ordered_prompts, evaluated_by_id)
        score = (
            weights["association"] * association
            + weights["path"] * path
            + weights["targetability"] * targetability
            + weights["stability"] * stability
            - weights["nuisance_penalty"] * penalty
        )
        evidence = _graph_evidence_from_evaluated(spec, scoring_evaluated)
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

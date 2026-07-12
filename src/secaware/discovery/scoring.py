from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from secaware.discovery.candidate_enum import FactorSpec
from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.hypotheses import FactorType
from secaware.schema.oracle import OracleRecord, SecurityLabel
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import MotifId, PromptTSGRecord
from secaware.tsg.graph import record_to_multidigraph
from secaware.tsg.motifs import find_motif_matches, has_factor_requirement


@dataclass(frozen=True, slots=True)
class EvaluatedPromptGraph:
    prompt_id: str
    graph_sha256: str
    factors: tuple[tuple[FactorType, bool], ...]
    motif_counts: tuple[tuple[MotifId, int], ...]

    def has_factor(self, factor_type: FactorType) -> bool:
        return dict(self.factors)[factor_type]

    def motif_count(self, motif_id: MotifId) -> int:
        return dict(self.motif_counts)[motif_id]


def _coordinate_error() -> SecAwareError:
    return SecAwareError(
        ErrorCode.ANALYSIS_INVALID,
        "discovery.coordinates",
        "discovery prompt graph coordinates are invalid",
    )


def _evaluate_prompt_tsgs(
    records: Sequence[PromptTSGRecord],
    *,
    factor_types: Sequence[FactorType] = (),
    motif_ids: Sequence[MotifId] = (),
) -> tuple[EvaluatedPromptGraph, ...]:
    evaluated: list[EvaluatedPromptGraph] = []
    seen: set[str] = set()
    for record in records:
        graph = record_to_multidigraph(record)
        prompt_id = record.prompt_id
        if prompt_id in seen:
            records = ()
            evaluated.clear()
            raise _coordinate_error() from None
        seen.add(prompt_id)
        evaluated.append(
            EvaluatedPromptGraph(
                prompt_id=prompt_id,
                graph_sha256=record.graph_sha256,
                factors=tuple(
                    (factor_type, has_factor_requirement(graph, factor_type))
                    for factor_type in factor_types
                ),
                motif_counts=tuple(
                    (motif_id, len(find_motif_matches(graph, motif_id))) for motif_id in motif_ids
                ),
            )
        )
    return tuple(evaluated)


def _risk_rate(records: Sequence[OracleRecord]) -> float:
    if not records:
        return 0.0
    insecure = sum(1 for record in records if record.security_label is SecurityLabel.INSECURE)
    return insecure / len(records)


def _revalidate_oracle(record: object) -> OracleRecord:
    return OracleRecord.model_validate(record)


def _validated_oracle_mapping(
    oracle_by_prompt: Mapping[str, Sequence[OracleRecord]],
) -> dict[str, tuple[OracleRecord, ...]]:
    validated: dict[str, tuple[OracleRecord, ...]] = {}
    for prompt_id, records in oracle_by_prompt.items():
        snapshots = tuple(_revalidate_oracle(record) for record in records)
        if type(prompt_id) is not str or any(record.prompt_id != prompt_id for record in snapshots):
            oracle_by_prompt = {}
            validated.clear()
            raise _coordinate_error() from None
        validated[prompt_id] = snapshots
    return validated


def _oracles_for_prompt_ids(
    prompt_ids: Sequence[str] | set[str],
    oracle_by_prompt: Mapping[str, Sequence[OracleRecord]],
) -> list[OracleRecord]:
    records: list[OracleRecord] = []
    for prompt_id in sorted(prompt_ids):
        records.extend(oracle_by_prompt.get(prompt_id, ()))
    return records


def association_score(
    spec: FactorSpec,
    prompt_tsgs: list[PromptTSGRecord],
    oracle_by_prompt: dict[str, list[OracleRecord]],
) -> tuple[float, float, dict[str, int]]:
    validated_oracles = _validated_oracle_mapping(oracle_by_prompt)
    evaluated = _evaluate_prompt_tsgs(prompt_tsgs, factor_types=(spec.factor_type,))
    present_ids = [item.prompt_id for item in evaluated if item.has_factor(spec.factor_type)]
    absent_ids = [item.prompt_id for item in evaluated if not item.has_factor(spec.factor_type)]
    present_oracles = _oracles_for_prompt_ids(present_ids, validated_oracles)
    absent_oracles = _oracles_for_prompt_ids(absent_ids, validated_oracles)
    joined_oracles = (*present_oracles, *absent_oracles)
    raw = _risk_rate(absent_oracles) - _risk_rate(present_oracles)
    support = {
        "n_total": len(evaluated),
        "n_present": len(present_ids),
        "n_absent": len(absent_ids),
        "n_insecure": sum(
            1 for record in joined_oracles if record.security_label is SecurityLabel.INSECURE
        ),
    }
    return max(0.0, raw), raw, support


def path_score(
    spec: FactorSpec,
    prompt_tsgs: list[PromptTSGRecord],
    oracle_by_prompt: dict[str, list[OracleRecord]],
) -> float:
    validated_oracles = _validated_oracle_mapping(oracle_by_prompt)
    evaluated = _evaluate_prompt_tsgs(
        prompt_tsgs,
        factor_types=(spec.factor_type,),
        motif_ids=(spec.motif_id,),
    )
    absent = [item for item in evaluated if not item.has_factor(spec.factor_type)]
    if not absent:
        return 0.0
    motif_absent = [item for item in absent if item.motif_count(spec.motif_id) >= 1]
    p_motif = len(motif_absent) / len(absent)
    motif_prompt_ids = {
        item.prompt_id for item in evaluated if item.motif_count(spec.motif_id) >= 1
    }
    motif_oracles = _oracles_for_prompt_ids(motif_prompt_ids, validated_oracles)
    score = p_motif * _risk_rate(motif_oracles)
    if spec.cwe != "generic" and any(
        finding.cwe == spec.cwe for record in motif_oracles for finding in record.findings
    ):
        score += 0.1
    return min(1.0, score)


def _validated_evaluated_mapping(
    records: Mapping[str, PromptTSGRecord],
    *,
    factor_type: FactorType,
) -> dict[str, EvaluatedPromptGraph]:
    evaluated = _evaluate_prompt_tsgs(list(records.values()), factor_types=(factor_type,))
    by_id = {item.prompt_id: item for item in evaluated}
    if set(records) != set(by_id) or any(key != records[key].prompt_id for key in records):
        records = {}
        by_id.clear()
        raise _coordinate_error() from None
    return by_id


def stability_score(
    spec: FactorSpec,
    prompts: list[PromptRecord],
    prompt_tsg_by_id: dict[str, PromptTSGRecord],
    oracle_by_prompt: dict[str, list[OracleRecord]],
) -> float:
    validated_oracles = _validated_oracle_mapping(oracle_by_prompt)
    evaluated = _validated_evaluated_mapping(
        prompt_tsg_by_id,
        factor_type=spec.factor_type,
    )
    groups: dict[str, list[EvaluatedPromptGraph]] = defaultdict(list)
    for prompt in prompts:
        if prompt.prompt_id not in evaluated:
            raise _coordinate_error() from None
        groups[prompt.task_family].append(evaluated[prompt.prompt_id])
    if len(groups) <= 1:
        return 0.5
    expected = 0
    for group in groups.values():
        present_ids = [item.prompt_id for item in group if item.has_factor(spec.factor_type)]
        absent_ids = [item.prompt_id for item in group if not item.has_factor(spec.factor_type)]
        raw = _risk_rate(_oracles_for_prompt_ids(absent_ids, validated_oracles)) - _risk_rate(
            _oracles_for_prompt_ids(present_ids, validated_oracles)
        )
        if present_ids and absent_ids and raw > 0:
            expected += 1
    return expected / len(groups)


def nuisance_penalty(
    spec: FactorSpec,
    prompts: list[PromptRecord],
    prompt_tsg_by_id: dict[str, PromptTSGRecord],
) -> float:
    if not prompts:
        return 0.0
    evaluated = _validated_evaluated_mapping(
        prompt_tsg_by_id,
        factor_type=spec.factor_type,
    )
    if any(prompt.prompt_id not in evaluated for prompt in prompts):
        raise _coordinate_error() from None
    values = [
        1.0 if evaluated[prompt.prompt_id].has_factor(spec.factor_type) else 0.0
        for prompt in prompts
    ]
    lengths = [float(len(prompt.prompt.split())) for prompt in prompts]
    if len(set(values)) <= 1 or len(set(lengths)) <= 1:
        length_corr_abs = 0.0
    else:
        mean_value = sum(values) / len(values)
        mean_length = sum(lengths) / len(lengths)
        covariance = sum(
            (value - mean_value) * (length - mean_length)
            for value, length in zip(values, lengths, strict=True)
        )
        value_variance = sum((value - mean_value) ** 2 for value in values)
        length_variance = sum((length - mean_length) ** 2 for length in lengths)
        length_corr_abs = (
            abs(covariance / math.sqrt(value_variance * length_variance))
            if value_variance and length_variance
            else 0.0
        )
    family_counts = Counter(
        prompt.task_family for prompt, value in zip(prompts, values, strict=True) if value
    )
    present_count = sum(family_counts.values())
    concentration = max(family_counts.values()) / present_count if present_count else 0.0
    scope_concentration_penalty = max(0.0, concentration - 0.8)
    return min(1.0, 0.5 * length_corr_abs + scope_concentration_penalty)


def graph_evidence_summary(
    spec: FactorSpec,
    prompt_tsgs: list[PromptTSGRecord],
) -> dict[str, Any]:
    evaluated = _evaluate_prompt_tsgs(prompt_tsgs, motif_ids=(spec.motif_id,))
    counts = [item.motif_count(spec.motif_id) for item in evaluated]
    return {
        "motif_id": spec.motif_id.value,
        "motif_prompt_count": sum(1 for count in counts if count >= 1),
        "motif_match_count": sum(counts),
        "graph_sha256": sorted({item.graph_sha256 for item in evaluated}),
    }


__all__ = [
    "association_score",
    "graph_evidence_summary",
    "nuisance_penalty",
    "path_score",
    "stability_score",
]

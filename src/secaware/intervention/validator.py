from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TypeVar, cast

import networkx as nx
from pydantic import BaseModel, ValidationError

from secaware.discovery.candidate_enum import FACTOR_SPECS
from secaware.errors import ErrorCode, SecAwareError
from secaware.extractors.prompt_tsg_extractor import extract_prompt_tsg
from secaware.schema.common import model_shape_is_intact
from secaware.schema.hypotheses import FactorType, HypothesisRecord
from secaware.schema.records import PromptRecord
from secaware.schema.tsg import MotifId, NodeType, PromptTSGRecord
from secaware.tsg.graph import record_to_multidigraph
from secaware.tsg.motifs import factor_query_vector, motif_query_vector


_ModelT = TypeVar("_ModelT", bound=BaseModel)


class _InvalidContract(Exception):
    pass


class _InvalidTSGContract(Exception):
    pass


class _FailureKind(Enum):
    TSG_INVALID = "tsg_invalid"
    ANALYSIS_INVALID = "analysis_invalid"


@dataclass(frozen=True, slots=True)
class PreparedIntervention:
    prompt: PromptRecord
    hypothesis: HypothesisRecord
    original_tsg: PromptTSGRecord = field(repr=False)
    original_graph: nx.MultiDiGraph = field(repr=False, compare=False)


def _tsg_error() -> SecAwareError:
    return SecAwareError(
        ErrorCode.TSG_INVALID,
        "intervention.validate",
        "intervention prompt graph validation failed",
    )


def _analysis_error() -> SecAwareError:
    return SecAwareError(
        ErrorCode.ANALYSIS_INVALID,
        "intervention.validate",
        "intervention analysis validation failed",
    )


def _strict_snapshot(model_type: type[_ModelT], value: object) -> _ModelT:
    if type(value) is not model_type or not model_shape_is_intact(value):
        raise _InvalidContract from None
    try:
        payload = value.model_dump(mode="python", round_trip=True, warnings=False)
        return model_type.model_validate(payload, strict=True)
    except (TypeError, ValueError, ValidationError):
        raise _InvalidContract from None


def _strict_tsg_snapshot(value: object) -> PromptTSGRecord:
    if type(value) is not PromptTSGRecord or not model_shape_is_intact(value):
        raise _InvalidTSGContract from None
    try:
        payload = value.model_dump(mode="python", round_trip=True, warnings=False)
        return PromptTSGRecord.model_validate(payload, strict=True)
    except (TypeError, ValueError, ValidationError):
        raise _InvalidTSGContract from None


def _validate_hypothesis_contract(hypothesis: HypothesisRecord) -> None:
    if type(hypothesis.factor_type) is not FactorType:
        raise _InvalidContract from None
    try:
        spec = FACTOR_SPECS[hypothesis.factor_type]
    except (KeyError, TypeError):
        raise _InvalidContract from None
    if (
        hypothesis.motif_id is not spec.motif_id
        or hypothesis.requirement_label != spec.requirement_label
        or hypothesis.guard_label != spec.guard_label
        or hypothesis.patch_operator != spec.patch_operator
        or hypothesis.expected_direction != "risk_down_when_added"
    ):
        raise _InvalidContract from None


def _snapshot_intervention_contract(
    prompt: PromptRecord,
    hypothesis: HypothesisRecord,
) -> tuple[PromptRecord, HypothesisRecord]:
    prompt_snapshot = _strict_snapshot(PromptRecord, prompt)
    hypothesis_snapshot = _strict_snapshot(HypothesisRecord, hypothesis)
    _validate_hypothesis_contract(hypothesis_snapshot)
    return prompt_snapshot, hypothesis_snapshot


def _same_canonical_record(one: PromptTSGRecord, two: PromptTSGRecord) -> bool:
    return one.model_dump_json() == two.model_dump_json()


def _prepare_intervention(
    prompt: PromptRecord,
    original_tsg: PromptTSGRecord,
    hypothesis: HypothesisRecord,
) -> PreparedIntervention:
    prompt_snapshot, hypothesis_snapshot = _snapshot_intervention_contract(prompt, hypothesis)
    tsg_snapshot = _strict_tsg_snapshot(original_tsg)
    original_graph = record_to_multidigraph(tsg_snapshot)
    expected_tsg = extract_prompt_tsg(prompt_snapshot)
    if not _same_canonical_record(tsg_snapshot, expected_tsg):
        raise _InvalidContract from None
    return PreparedIntervention(
        prompt=prompt_snapshot,
        hypothesis=hypothesis_snapshot,
        original_tsg=tsg_snapshot,
        original_graph=nx.freeze(original_graph),
    )


def _semantic_labels(graph: nx.MultiDiGraph, node_type: NodeType) -> tuple[str, ...]:
    return tuple(
        sorted(
            attributes["label"]
            for _, attributes in graph.nodes(data=True)
            if attributes["node_type"] is node_type
        )
    )


def _has_non_target_change(
    original_factors: dict[FactorType, bool],
    counter_factors: dict[FactorType, bool],
    original_motifs: dict[MotifId, bool],
    counter_motifs: dict[MotifId, bool],
    *,
    target_factor: FactorType,
    target_motif: MotifId,
) -> bool:
    return any(
        original_factors[factor] != counter_factors[factor]
        for factor in FactorType
        if factor is not target_factor
    ) or any(
        original_motifs[motif] != counter_motifs[motif]
        for motif in MotifId
        if motif is not target_motif
    )


def _validate_prepared(
    prepared: PreparedIntervention,
    counterfactual_prompt: str,
) -> dict[str, bool]:
    if type(prepared) is not PreparedIntervention or type(counterfactual_prompt) is not str:
        raise _InvalidContract from None
    try:
        counterfactual_record = PromptRecord.model_validate(
            {
                "prompt_id": prepared.prompt.prompt_id,
                "task_id": prepared.prompt.task_id,
                "split": prepared.prompt.split,
                "language": prepared.prompt.language,
                "task_family": prepared.prompt.task_family,
                "cwe": prepared.prompt.cwe,
                "prompt": counterfactual_prompt,
            },
            strict=True,
        )
    except ValidationError:
        raise _InvalidContract from None

    counterfactual_tsg = extract_prompt_tsg(counterfactual_record)
    counter_graph = record_to_multidigraph(counterfactual_tsg)
    if counterfactual_tsg.prompt_id != prepared.prompt.prompt_id:
        raise _InvalidContract from None

    original_factors = dict(factor_query_vector(prepared.original_graph))
    counter_factors = dict(factor_query_vector(counter_graph))
    original_motifs = dict(motif_query_vector(prepared.original_graph))
    counter_motifs = dict(motif_query_vector(counter_graph))
    target_factor = prepared.hypothesis.factor_type
    target_motif = prepared.hypothesis.motif_id

    counter_target_valid = counter_factors[target_factor] and not counter_motifs[target_motif]
    semantic_valid = (
        (
            prepared.prompt.prompt_id,
            prepared.prompt.split,
            prepared.prompt.language,
            prepared.prompt.task_family,
            prepared.prompt.cwe,
        )
        == (
            counterfactual_record.prompt_id,
            counterfactual_record.split,
            counterfactual_record.language,
            counterfactual_record.task_family,
            counterfactual_record.cwe,
        )
        and _semantic_labels(prepared.original_graph, NodeType.TASK_OPERATION)
        == _semantic_labels(counter_graph, NodeType.TASK_OPERATION)
        and _semantic_labels(prepared.original_graph, NodeType.SINK)
        == _semantic_labels(counter_graph, NodeType.SINK)
    )
    return {
        "round_trip_valid": bool(counter_target_valid),
        "semantic_valid": bool(semantic_valid),
        "target_changed": bool(
            not original_factors[target_factor]
            and counter_factors[target_factor]
            and counter_target_valid
        ),
        "side_effect": _has_non_target_change(
            original_factors,
            counter_factors,
            original_motifs,
            counter_motifs,
            target_factor=target_factor,
            target_motif=target_motif,
        ),
    }


def _try_validate(
    prompt: PromptRecord,
    original_tsg: PromptTSGRecord,
    counterfactual_prompt: str,
    hypothesis: HypothesisRecord,
) -> dict[str, bool] | _FailureKind:
    try:
        prepared = _prepare_intervention(prompt, original_tsg, hypothesis)
        return _validate_prepared(prepared, counterfactual_prompt)
    except _InvalidTSGContract:
        return _FailureKind.TSG_INVALID
    except _InvalidContract:
        return _FailureKind.ANALYSIS_INVALID
    except SecAwareError as error:
        if error.code is ErrorCode.TSG_INVALID:
            return _FailureKind.TSG_INVALID
        return _FailureKind.ANALYSIS_INVALID
    except Exception:
        return _FailureKind.ANALYSIS_INVALID


def validate_intervention(
    prompt: PromptRecord,
    original_tsg: PromptTSGRecord,
    counterfactual_prompt: str,
    hypothesis: HypothesisRecord,
) -> dict[str, bool]:
    result = _try_validate(prompt, original_tsg, counterfactual_prompt, hypothesis)
    prompt = cast(PromptRecord, None)
    original_tsg = cast(PromptTSGRecord, None)
    counterfactual_prompt = cast(str, None)
    hypothesis = cast(HypothesisRecord, None)
    if result is _FailureKind.TSG_INVALID:
        raise _tsg_error() from None
    if result is _FailureKind.ANALYSIS_INVALID:
        raise _analysis_error() from None
    return result


__all__ = ["validate_intervention"]

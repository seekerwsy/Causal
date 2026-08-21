from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import math
import random

from secaware.dataset_adjudication.packets import AdjudicationPacketSet
from secaware.dataset_adjudication.schema import (
    CodexDecision,
    DecisionConfidence,
    HumanReviewQueueEntry,
    RepeatConsistencyRecord,
    ReviewReason,
)


@dataclass(frozen=True, slots=True)
class ReconciliationResult:
    consistency: tuple[RepeatConsistencyRecord, ...]
    human_review_queue: tuple[HumanReviewQueueEntry, ...]
    summary: dict[str, object]


def _decision_map(
    decisions: list[CodexDecision],
    *,
    pass_id: str,
) -> dict[str, CodexDecision]:
    values: dict[str, CodexDecision] = {}
    for decision in decisions:
        if decision.pass_id != pass_id:
            raise ValueError(f"pass {pass_id} decision file contains the wrong pass ID")
        if decision.packet_id in values:
            raise ValueError(f"pass {pass_id} decisions contain a duplicate packet")
        values[decision.packet_id] = decision
    return values


def _derived_seed(seed: int, dimension: str, source_stratum: str) -> int:
    value = f"human-audit-sample-v1\0{seed}\0{dimension}\0{source_stratum}"
    return int.from_bytes(hashlib.sha256(value.encode()).digest()[:8], "big")


def _validate_decisions(
    packet_set: AdjudicationPacketSet,
    pass_a: dict[str, CodexDecision],
    pass_b: dict[str, CodexDecision],
) -> None:
    metadata = {item.packet_id: item for item in packet_set.metadata}
    expected = set(metadata)
    if set(pass_a) != expected or set(pass_b) != expected:
        raise ValueError("Codex decision coverage does not match the packet set")
    manifest_digests = {
        decision.input_manifest_sha256 for decision in (*pass_a.values(), *pass_b.values())
    }
    if len(manifest_digests) != 1:
        raise ValueError("Codex decisions do not share one input manifest digest")
    visible_by_pass = {
        "A": {item.packet_id: item for item in packet_set.pass_a},
        "B": {item.packet_id: item for item in packet_set.pass_b},
    }
    for packet_id, packet_metadata in metadata.items():
        for decision in (pass_a[packet_id], pass_b[packet_id]):
            if decision.dimension is not packet_metadata.dimension:
                raise ValueError("Codex decision dimension does not match packet metadata")
            if decision.packet_digest != packet_metadata.packet_digest:
                raise ValueError("Codex decision packet digest is stale")
            packet = visible_by_pass[decision.pass_id][packet_id]
            visible = "\n".join(
                value
                for field in ("prompt", "prompt_a", "prompt_b")
                if isinstance((value := getattr(packet, field, None)), str)
            )
            if any(quote not in visible for quote in decision.evidence_quotes):
                raise ValueError("Codex decision evidence is not an exact visible quote")


def _audit_sample(
    candidates: list[str],
    metadata_by_id,
    *,
    audit_fraction: float,
    seed: int,
) -> set[str]:
    strata: dict[tuple[str, str], list[str]] = {}
    for packet_id in sorted(candidates):
        metadata = metadata_by_id[packet_id]
        key = (metadata.dimension.value, metadata.source_stratum)
        strata.setdefault(key, []).append(packet_id)
    selected: set[str] = set()
    for (dimension, source_stratum), packet_ids in sorted(strata.items()):
        ordered = sorted(packet_ids)
        random.Random(_derived_seed(seed, dimension, source_stratum)).shuffle(ordered)
        count = max(1, math.ceil(len(ordered) * audit_fraction))
        selected.update(ordered[:count])
    return selected


def reconcile_codex_passes(
    packet_set: AdjudicationPacketSet,
    pass_a_decisions: list[CodexDecision],
    pass_b_decisions: list[CodexDecision],
    *,
    audit_fraction: float,
    seed: int,
) -> ReconciliationResult:
    if not 0 < audit_fraction <= 1:
        raise ValueError("human audit fraction must be in (0, 1]")
    pass_a = _decision_map(pass_a_decisions, pass_id="A")
    pass_b = _decision_map(pass_b_decisions, pass_id="B")
    _validate_decisions(packet_set, pass_a, pass_b)
    metadata_by_id = {item.packet_id: item for item in packet_set.metadata}

    consistency: list[RepeatConsistencyRecord] = []
    reasons_by_id: dict[str, set[ReviewReason]] = {}
    audit_candidates: list[str] = []
    for packet_id in sorted(metadata_by_id):
        metadata = metadata_by_id[packet_id]
        left = pass_a[packet_id]
        right = pass_b[packet_id]
        labels_agree = left.label == right.label
        consistency.append(
            RepeatConsistencyRecord(
                packet_id=packet_id,
                dimension=metadata.dimension,
                source_stratum=metadata.source_stratum,
                pass_a_label=left.label.value,
                pass_b_label=right.label.value,
                pass_a_confidence=left.confidence,
                pass_b_confidence=right.confidence,
                labels_agree=labels_agree,
            )
        )
        reasons: set[ReviewReason] = set()
        if not labels_agree:
            reasons.add(ReviewReason.PASS_DISAGREEMENT)
        if (
            left.confidence is DecisionConfidence.LOW
            or right.confidence is DecisionConfidence.LOW
        ):
            reasons.add(ReviewReason.LOW_CONFIDENCE)
        if reasons:
            reasons_by_id[packet_id] = reasons
        else:
            audit_candidates.append(packet_id)

    for packet_id in _audit_sample(
        audit_candidates,
        metadata_by_id,
        audit_fraction=audit_fraction,
        seed=seed,
    ):
        reasons_by_id[packet_id] = {ReviewReason.STRATIFIED_AUDIT}

    reason_order = {reason: index for index, reason in enumerate(ReviewReason)}
    human_review_queue = tuple(
        HumanReviewQueueEntry(
            packet_id=packet_id,
            dimension=metadata_by_id[packet_id].dimension,
            source_stratum=metadata_by_id[packet_id].source_stratum,
            packet_digest=metadata_by_id[packet_id].packet_digest,
            review_reasons=tuple(sorted(reasons, key=reason_order.__getitem__)),
            pass_a_label=pass_a[packet_id].label.value,
            pass_b_label=pass_b[packet_id].label.value,
            pass_a_confidence=pass_a[packet_id].confidence,
            pass_b_confidence=pass_b[packet_id].confidence,
        )
        for packet_id, reasons in sorted(reasons_by_id.items())
    )
    agreement_count = sum(item.labels_agree for item in consistency)
    reason_counts = Counter(
        reason.value for item in human_review_queue for reason in item.review_reasons
    )
    label_distributions: dict[str, dict[str, dict[str, int]]] = {}
    for pass_id, decisions in (("pass_a", pass_a), ("pass_b", pass_b)):
        by_dimension: dict[str, Counter[str]] = {}
        for decision in decisions.values():
            by_dimension.setdefault(decision.dimension.value, Counter())[decision.label.value] += 1
        label_distributions[pass_id] = {
            dimension: dict(sorted(counts.items()))
            for dimension, counts in sorted(by_dimension.items())
        }
    summary: dict[str, object] = {
        "status": "AWAITING_HUMAN_AUDIT",
        "metric_name": "codex_repeat_consistency",
        "packet_count": len(consistency),
        "agreement_count": agreement_count,
        "raw_agreement": agreement_count / len(consistency) if consistency else 0.0,
        "human_review_count": len(human_review_queue),
        "review_reason_counts": dict(sorted(reason_counts.items())),
        "label_distributions": label_distributions,
        "audit_fraction": audit_fraction,
        "audit_seed": seed,
        "audit_version": "human-audit-sample-v1",
    }
    return ReconciliationResult(
        tuple(consistency),
        human_review_queue,
        summary,
    )


__all__ = ["ReconciliationResult", "reconcile_codex_passes"]

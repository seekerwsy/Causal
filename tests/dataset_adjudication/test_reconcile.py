from __future__ import annotations

from datetime import UTC, datetime

import pytest

from secaware.dataset_adjudication.packets import (
    build_adjudication_packets,
    subset_adjudication_packets,
)
from secaware.dataset_adjudication.reconcile import reconcile_codex_passes
from secaware.dataset_adjudication.schema import (
    AdjudicationDimension,
    ClusterAdjudicationLabel,
    ClusterCodexDecision,
    DecisionConfidence,
    NeutralityAdjudicationLabel,
    NeutralityCodexDecision,
    ReviewReason,
)
from secaware.dataset_audit.schema import (
    CweEvidence,
    FunctionalState,
    NeutralityState,
    RecordAudit,
    SourceCoordinate,
)


def _record(source: str, line: int, prompt: str, neutrality: NeutralityState) -> RecordAudit:
    return RecordAudit(
        schema_version="1.0",
        coordinate=SourceCoordinate(
            source_id=source,
            relative_path=f"{source}.jsonl",
            line_number=line,
            record_id=f"{source}-{line}",
        ),
        prompt=prompt,
        language="python",
        cwe_ids=("CWE-89",),
        cwe_evidence=CweEvidence.EXPLICIT_FIELD,
        exact_prompt_sha256=f"exact-{source}-{line}",
        normalized_prompt_sha256=f"normalized-{source}-{line}",
        neutrality=neutrality,
        neutrality_rule_version="neutrality-prescreen-v1",
        functional_state=FunctionalState.ABSENT,
        task_cluster_id=f"cluster-{source}-{line}",
        cluster_independence_resolved=True,
    )


def _records() -> list[RecordAudit]:
    return [
        _record("alpha", 1, "Validate a user token.", NeutralityState.UNRESOLVED),
        _record("alpha", 2, "Safely parse a user token.", NeutralityState.UNRESOLVED),
        _record("alpha", 3, "Prevent SQL injection.", NeutralityState.OBVIOUS_CONFLICT),
        _record("beta", 4, "Authenticate a user.", NeutralityState.UNRESOLVED),
        _record(
            "gamma",
            5,
            "Implement a function to read a user supplied file safely.",
            NeutralityState.CANDIDATE_NEUTRAL,
        ),
        _record(
            "gamma",
            6,
            "Implement a function to read the user supplied file safely.",
            NeutralityState.CANDIDATE_NEUTRAL,
        ),
    ]


def _decisions(packet_set, pass_id: str):
    decisions = []
    for packet in packet_set.pass_a if pass_id == "A" else packet_set.pass_b:
        visible_quote = (
            packet.prompt
            if packet.dimension is AdjudicationDimension.NEUTRALITY
            else packet.prompt_a
        )
        common = {
            "packet_id": packet.packet_id,
            "pass_id": pass_id,
            "packet_digest": packet.packet_digest,
            "confidence": DecisionConfidence.HIGH,
            "evidence_quotes": (visible_quote,),
            "rationale": "The frozen rubric supports this label.",
            "rubric_version": "adjudication-rubric-v1",
            "annotator_kind": "CODEX",
            "annotator_id": "codex-primary",
            "decision_timestamp": datetime(2026, 8, 12, tzinfo=UTC),
            "input_manifest_sha256": "a" * 64,
        }
        if packet.dimension is AdjudicationDimension.NEUTRALITY:
            decisions.append(
                NeutralityCodexDecision(
                    dimension=AdjudicationDimension.NEUTRALITY,
                    label=NeutralityAdjudicationLabel.ELIGIBLE_NEUTRAL,
                    **common,
                )
            )
        else:
            decisions.append(
                ClusterCodexDecision(
                    dimension=AdjudicationDimension.CLUSTER_RELATION,
                    label=ClusterAdjudicationLabel.SAME_TASK_VARIANT,
                    **common,
                )
            )
    return decisions


def test_reconciliation_routes_disagreement_low_confidence_and_stratified_audit() -> None:
    packet_set = build_adjudication_packets(_records(), seed=20260812)
    pass_a = _decisions(packet_set, "A")
    pass_b = _decisions(packet_set, "B")
    by_id_b = {item.packet_id: item for item in pass_b}
    neutrality_ids = [
        item.packet_id
        for item in packet_set.metadata
        if item.dimension is AdjudicationDimension.NEUTRALITY
    ]
    disagreement_id, low_id = neutrality_ids[:2]
    by_id_b[disagreement_id] = by_id_b[disagreement_id].model_copy(
        update={"label": NeutralityAdjudicationLabel.INELIGIBLE_SECURITY_CONSTRAINT}
    )
    by_id_b[low_id] = by_id_b[low_id].model_copy(
        update={"confidence": DecisionConfidence.LOW}
    )

    result = reconcile_codex_passes(
        packet_set,
        pass_a,
        list(by_id_b.values()),
        audit_fraction=0.2,
        seed=20260812,
    )
    queue = {item.packet_id: item for item in result.human_review_queue}

    assert ReviewReason.PASS_DISAGREEMENT in queue[disagreement_id].review_reasons
    assert ReviewReason.LOW_CONFIDENCE in queue[low_id].review_reasons
    assert any(
        ReviewReason.STRATIFIED_AUDIT in item.review_reasons
        for item in result.human_review_queue
    )
    assert result.summary["status"] == "AWAITING_HUMAN_AUDIT"
    assert result.summary["metric_name"] == "codex_repeat_consistency"
    assert "human_inter_rater" not in result.summary


def test_agreement_audit_is_deterministic_and_samples_each_nonempty_stratum() -> None:
    packet_set = build_adjudication_packets(_records(), seed=20260812)
    pass_a = _decisions(packet_set, "A")
    pass_b = _decisions(packet_set, "B")

    first = reconcile_codex_passes(
        packet_set,
        pass_a,
        pass_b,
        audit_fraction=0.2,
        seed=20260812,
    )
    second = reconcile_codex_passes(
        packet_set,
        list(reversed(pass_a)),
        list(reversed(pass_b)),
        audit_fraction=0.2,
        seed=20260812,
    )

    assert first == second
    audited = [
        item
        for item in first.human_review_queue
        if ReviewReason.STRATIFIED_AUDIT in item.review_reasons
    ]
    expected_strata = {
        (item.dimension, item.source_stratum) for item in packet_set.metadata
    }
    assert {(item.dimension, item.source_stratum) for item in audited} == expected_strata


def test_reconciliation_rejects_missing_duplicate_and_stale_decisions() -> None:
    packet_set = build_adjudication_packets(_records(), seed=20260812)
    pass_a = _decisions(packet_set, "A")
    pass_b = _decisions(packet_set, "B")

    with pytest.raises(ValueError, match="coverage"):
        reconcile_codex_passes(
            packet_set,
            pass_a[:-1],
            pass_b,
            audit_fraction=0.2,
            seed=20260812,
        )
    with pytest.raises(ValueError, match="duplicate"):
        reconcile_codex_passes(
            packet_set,
            [*pass_a, pass_a[0]],
            pass_b,
            audit_fraction=0.2,
            seed=20260812,
        )
    stale = pass_a.copy()
    stale[0] = stale[0].model_copy(update={"packet_digest": "b" * 64})
    with pytest.raises(ValueError, match="digest"):
        reconcile_codex_passes(
            packet_set,
            stale,
            pass_b,
            audit_fraction=0.2,
            seed=20260812,
        )
    missing_quote = pass_a.copy()
    missing_quote[0] = missing_quote[0].model_copy(
        update={"evidence_quotes": ("not present in the blinded packet",)}
    )
    with pytest.raises(ValueError, match="exact visible quote"):
        reconcile_codex_passes(
            packet_set,
            missing_quote,
            pass_b,
            audit_fraction=0.2,
            seed=20260812,
        )


def test_pilot_subset_preserves_blinded_order_and_limits_decision_coverage() -> None:
    packet_set = build_adjudication_packets(_records(), seed=20260812)
    selected = {item.packet_id for item in packet_set.metadata[:2]}

    pilot = subset_adjudication_packets(packet_set, selected)

    assert {item.packet_id for item in pilot.metadata} == selected
    assert [item.packet_id for item in pilot.pass_a] == [
        item.packet_id for item in packet_set.pass_a if item.packet_id in selected
    ]
    assert [item.packet_id for item in pilot.pass_b] == [
        item.packet_id for item in packet_set.pass_b if item.packet_id in selected
    ]
    result = reconcile_codex_passes(
        pilot,
        [item for item in _decisions(packet_set, "A") if item.packet_id in selected],
        [item for item in _decisions(packet_set, "B") if item.packet_id in selected],
        audit_fraction=0.2,
        seed=20260812,
    )
    assert result.summary["packet_count"] == 2
    assert result.summary["label_distributions"]

    with pytest.raises(ValueError, match="unknown"):
        subset_adjudication_packets(packet_set, {*selected, "neutrality-" + "0" * 20})

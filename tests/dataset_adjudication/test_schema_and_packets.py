from __future__ import annotations

from secaware.dataset_adjudication.packets import build_adjudication_packets
from secaware.dataset_adjudication.schema import AdjudicationDimension
from secaware.dataset_audit.schema import (
    CweEvidence,
    FunctionalState,
    NeutralityState,
    RecordAudit,
    SourceCoordinate,
)


def _record(
    source: str,
    line: int,
    prompt: str,
    *,
    neutrality: NeutralityState,
    cwe: CweEvidence = CweEvidence.EXPLICIT_FIELD,
) -> RecordAudit:
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
        cwe_ids=("CWE-89",) if cwe is not CweEvidence.UNRESOLVED else (),
        cwe_evidence=cwe,
        exact_prompt_sha256=f"exact-{source}-{line}",
        normalized_prompt_sha256=f"normalized-{source}-{line}",
        neutrality=neutrality,
        neutrality_rule_version="neutrality-prescreen-v1",
        functional_state=FunctionalState.ABSENT,
        task_cluster_id=f"cluster-{source}-{line}",
        cluster_independence_resolved=True,
    )


def _fixture_records() -> list[RecordAudit]:
    return [
        _record(
            "security-a",
            1,
            "Implement a parser that validates a supplied token.",
            neutrality=NeutralityState.UNRESOLVED,
        ),
        _record(
            "security-b",
            2,
            "Implement a parser and prevent SQL injection.",
            neutrality=NeutralityState.OBVIOUS_CONFLICT,
        ),
        _record(
            "general",
            3,
            "Compute the factorial of an integer.",
            neutrality=NeutralityState.CANDIDATE_NEUTRAL,
            cwe=CweEvidence.UNRESOLVED,
        ),
        _record(
            "security-c",
            4,
            "Implement a function to read a user supplied file safely.",
            neutrality=NeutralityState.CANDIDATE_NEUTRAL,
        ),
        _record(
            "security-c",
            5,
            "Implement a function to read the user supplied file safely.",
            neutrality=NeutralityState.CANDIDATE_NEUTRAL,
        ),
    ]


def test_packet_builder_selects_only_frozen_neutrality_and_cluster_units() -> None:
    packet_set = build_adjudication_packets(_fixture_records(), seed=20260812)

    neutrality = [
        item
        for item in packet_set.metadata
        if item.dimension is AdjudicationDimension.NEUTRALITY
    ]
    clusters = [
        item
        for item in packet_set.metadata
        if item.dimension is AdjudicationDimension.CLUSTER_RELATION
    ]

    assert len(neutrality) == 2
    assert len(clusters) == 1
    assert {item.automatic_state for item in neutrality} == {
        "UNRESOLVED",
        "OBVIOUS_CONFLICT",
    }
    assert clusters[0].similarity is not None
    assert clusters[0].item_keys == ("security-c:4", "security-c:5")


def test_blinded_packets_do_not_expose_provenance_or_automatic_labels() -> None:
    packet_set = build_adjudication_packets(_fixture_records(), seed=20260812)

    for packet in (*packet_set.pass_a, *packet_set.pass_b):
        fields = packet.model_dump(mode="json")
        assert "source_id" not in fields
        assert "source_ids" not in fields
        assert "item_keys" not in fields
        assert "cwe_ids" not in fields
        assert "automatic_state" not in fields
        assert "similarity" not in fields
        assert "evidence_spans" not in fields


def test_passes_are_deterministic_and_reverse_cluster_prompt_presentation() -> None:
    records = _fixture_records()
    first = build_adjudication_packets(records, seed=20260812)
    reordered = build_adjudication_packets(list(reversed(records)), seed=20260812)

    assert first == reordered
    assert [item.packet_id for item in first.pass_a] != [
        item.packet_id for item in first.pass_b
    ]

    cluster_id = next(
        item.packet_id
        for item in first.metadata
        if item.dimension is AdjudicationDimension.CLUSTER_RELATION
    )
    pass_a = next(item for item in first.pass_a if item.packet_id == cluster_id)
    pass_b = next(item for item in first.pass_b if item.packet_id == cluster_id)
    assert pass_a.prompt_a == pass_b.prompt_b
    assert pass_a.prompt_b == pass_b.prompt_a
    assert pass_a.packet_digest == pass_b.packet_digest


def test_packet_ids_change_when_blinded_content_changes() -> None:
    records = _fixture_records()
    original = build_adjudication_packets(records, seed=20260812)
    changed = records.copy()
    changed[0] = _record(
        "security-a",
        1,
        "Implement a parser that validates two supplied tokens.",
        neutrality=NeutralityState.UNRESOLVED,
    )

    updated = build_adjudication_packets(changed, seed=20260812)
    original_ids = {
        item.packet_id
        for item in original.metadata
        if item.dimension is AdjudicationDimension.NEUTRALITY
    }
    updated_ids = {
        item.packet_id
        for item in updated.metadata
        if item.dimension is AdjudicationDimension.NEUTRALITY
    }
    assert original_ids != updated_ids

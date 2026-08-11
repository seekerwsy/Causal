from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import random
from typing import Literal

from secaware.dataset_adjudication.schema import (
    AdjudicationDimension,
    BlindedClusterPacket,
    BlindedNeutralityPacket,
    BlindedPacket,
    PacketMetadata,
)
from secaware.dataset_audit.clustering import ClusterItem, build_task_clusters
from secaware.dataset_audit.schema import NeutralityState, RecordAudit


@dataclass(frozen=True, slots=True)
class AdjudicationPacketSet:
    metadata: tuple[PacketMetadata, ...]
    pass_a: tuple[BlindedPacket, ...]
    pass_b: tuple[BlindedPacket, ...]


def _sha256(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _item_key(record: RecordAudit) -> str:
    return f"{record.coordinate.source_id}:{record.coordinate.line_number}"


def _derived_seed(seed: int, purpose: str) -> int:
    digest = hashlib.sha256(f"adjudication-packets-v1\0{seed}\0{purpose}".encode()).digest()
    return int.from_bytes(digest[:8], "big")


def _ordered_pass_ids(packet_ids: list[str], *, seed: int) -> tuple[list[str], list[str]]:
    pass_a = sorted(packet_ids)
    pass_b = sorted(packet_ids)
    random.Random(_derived_seed(seed, "pass-a-order")).shuffle(pass_a)
    random.Random(_derived_seed(seed, "pass-b-order")).shuffle(pass_b)
    if len(pass_a) > 1 and pass_a == pass_b:
        pass_b.reverse()
    return pass_a, pass_b


def _neutrality_packet(record: RecordAudit) -> tuple[PacketMetadata, str]:
    if not record.prompt:
        raise ValueError("selected neutrality record has no prompt")
    item_key = _item_key(record)
    packet_digest = _sha256(
        {
            "dimension": AdjudicationDimension.NEUTRALITY.value,
            "prompt": record.prompt,
        }
    )
    packet_id = f"neutrality-{_sha256([item_key, packet_digest])[:20]}"
    metadata = PacketMetadata(
        packet_id=packet_id,
        dimension=AdjudicationDimension.NEUTRALITY,
        source_stratum=record.coordinate.source_id,
        item_keys=(item_key,),
        source_ids=(record.coordinate.source_id,),
        automatic_state=record.neutrality.value,
        evidence_spans=record.neutrality_evidence_spans,
        packet_digest=packet_digest,
    )
    return metadata, record.prompt


def _cluster_packet(
    left: RecordAudit,
    right: RecordAudit,
    *,
    similarity: float,
) -> tuple[PacketMetadata, tuple[str, str]]:
    if not left.prompt or not right.prompt:
        raise ValueError("selected cluster relation has a missing prompt")
    ordered = sorted((left, right), key=_item_key)
    left, right = ordered
    item_keys = (_item_key(left), _item_key(right))
    prompts = (left.prompt, right.prompt)
    packet_digest = _sha256(
        {
            "dimension": AdjudicationDimension.CLUSTER_RELATION.value,
            "prompts": prompts,
        }
    )
    packet_id = f"cluster-rel-{_sha256([*item_keys, packet_digest])[:20]}"
    source_ids = (left.coordinate.source_id, right.coordinate.source_id)
    source_stratum = source_ids[0] if source_ids[0] == source_ids[1] else "cross_dataset"
    metadata = PacketMetadata(
        packet_id=packet_id,
        dimension=AdjudicationDimension.CLUSTER_RELATION,
        source_stratum=source_stratum,
        item_keys=item_keys,
        source_ids=source_ids,
        automatic_state="AMBIGUOUS_TEXT_SIMILARITY",
        similarity=similarity,
        packet_digest=packet_digest,
    )
    return metadata, prompts


def _blinded_packet(
    metadata: PacketMetadata,
    content: str | tuple[str, str],
    *,
    pass_id: Literal["A", "B"],
    seed: int,
) -> BlindedPacket:
    if metadata.dimension is AdjudicationDimension.NEUTRALITY:
        if not isinstance(content, str):
            raise TypeError("neutrality content must be one prompt")
        return BlindedNeutralityPacket(
            packet_id=metadata.packet_id,
            dimension=AdjudicationDimension.NEUTRALITY,
            pass_id=pass_id,
            packet_digest=metadata.packet_digest,
            prompt=content,
        )
    if isinstance(content, str):
        raise TypeError("cluster relation content must be a prompt pair")
    orientation = _derived_seed(seed, metadata.packet_id) % 2
    if pass_id == "B":
        orientation = 1 - orientation
    prompt_a, prompt_b = content if orientation == 0 else tuple(reversed(content))
    return BlindedClusterPacket(
        packet_id=metadata.packet_id,
        dimension=AdjudicationDimension.CLUSTER_RELATION,
        pass_id=pass_id,
        packet_digest=metadata.packet_digest,
        prompt_a=prompt_a,
        prompt_b=prompt_b,
    )


def build_adjudication_packets(
    records: list[RecordAudit],
    *,
    seed: int,
) -> AdjudicationPacketSet:
    ordered = sorted(records, key=_item_key)
    if len({_item_key(record) for record in ordered}) != len(ordered):
        raise ValueError("record audit coordinates must be unique")
    by_key = {_item_key(record): record for record in ordered}
    metadata: list[PacketMetadata] = []
    content_by_id: dict[str, str | tuple[str, str]] = {}

    selected_states = {NeutralityState.UNRESOLVED, NeutralityState.OBVIOUS_CONFLICT}
    for record in ordered:
        if record.neutrality not in selected_states:
            continue
        packet_metadata, content = _neutrality_packet(record)
        metadata.append(packet_metadata)
        content_by_id[packet_metadata.packet_id] = content

    cluster_result = build_task_clusters(
        [
            ClusterItem(
                item_key=_item_key(record),
                source_id=record.coordinate.source_id,
                line_number=record.coordinate.line_number,
                record_id=record.coordinate.record_id,
                exact_prompt_sha256=record.exact_prompt_sha256,
                normalized_prompt_sha256=record.normalized_prompt_sha256,
                prompt=record.prompt,
            )
            for record in ordered
        ]
    )
    for relation in cluster_result.unresolved_relations:
        packet_metadata, content = _cluster_packet(
            by_key[relation.left_item_key],
            by_key[relation.right_item_key],
            similarity=float(relation.evidence_value),
        )
        metadata.append(packet_metadata)
        content_by_id[packet_metadata.packet_id] = content

    metadata = sorted(metadata, key=lambda item: item.packet_id)
    if len({item.packet_id for item in metadata}) != len(metadata):
        raise ValueError("adjudication packet identifiers must be unique")
    pass_a_ids, pass_b_ids = _ordered_pass_ids(
        [item.packet_id for item in metadata],
        seed=seed,
    )
    metadata_by_id = {item.packet_id: item for item in metadata}
    pass_a = tuple(
        _blinded_packet(
            metadata_by_id[packet_id],
            content_by_id[packet_id],
            pass_id="A",
            seed=seed,
        )
        for packet_id in pass_a_ids
    )
    pass_b = tuple(
        _blinded_packet(
            metadata_by_id[packet_id],
            content_by_id[packet_id],
            pass_id="B",
            seed=seed,
        )
        for packet_id in pass_b_ids
    )
    return AdjudicationPacketSet(tuple(metadata), pass_a, pass_b)


__all__ = ["AdjudicationPacketSet", "build_adjudication_packets"]

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import random
from typing import Literal

from secaware.dataset_audit.schema import FunctionalState, NeutralityState


SPLIT_VERSION = "cluster-split-v1"
SplitLabel = Literal["discover", "confirm", "UNRESOLVED"]


@dataclass(frozen=True, slots=True)
class SplitRecord:
    record_key: str
    cluster_id: str
    source_id: str
    language: str | None
    cwe_ids: tuple[str, ...]
    neutrality: NeutralityState
    functional_state: FunctionalState
    independence_resolved: bool


@dataclass(frozen=True, slots=True)
class SplitAssignment:
    record_key: str
    cluster_id: str
    split: SplitLabel


@dataclass(frozen=True, slots=True)
class SplitSimulation:
    discover_ratio: float
    seed: int
    version: str
    assignments: tuple[SplitAssignment, ...]
    independent_cluster_ids: tuple[str, ...]
    unresolved_cluster_ids: tuple[str, ...]
    summary: dict[str, object]


@dataclass(frozen=True, slots=True)
class SplitSimulationResult:
    simulations: tuple[SplitSimulation, ...]


def _derived_seed(seed: int, ratio: float, stratum: tuple[str, str]) -> int:
    value = f"{SPLIT_VERSION}\0{seed}\0{ratio:.6f}\0{stratum[0]}\0{stratum[1]}"
    return int.from_bytes(hashlib.sha256(value.encode("utf-8")).digest()[:8], "big")


def _counts(records: list[SplitRecord], field: str) -> dict[str, int]:
    if field == "cwe_ids":
        values = [cwe for record in records for cwe in record.cwe_ids]
    else:
        values = [str(getattr(record, field)) for record in records if getattr(record, field)]
    return dict(sorted(Counter(values).items()))


def _one_simulation(
    records: list[SplitRecord],
    ratio: float,
    seed: int,
    minimum_cluster_floor: int,
) -> SplitSimulation:
    if not 0 < ratio < 1:
        raise ValueError("discover ratios must be between zero and one")
    by_cluster: dict[str, list[SplitRecord]] = {}
    for record in records:
        by_cluster.setdefault(record.cluster_id, []).append(record)
    unresolved = {
        cluster_id
        for cluster_id, members in by_cluster.items()
        if not all(member.independence_resolved for member in members)
    }
    independent = sorted(set(by_cluster) - unresolved)
    strata: dict[tuple[str, str], list[str]] = {}
    for cluster_id in independent:
        members = sorted(by_cluster[cluster_id], key=lambda item: item.record_key)
        sources = Counter(item.source_id for item in members)
        primary_source = sorted(sources, key=lambda value: (-sources[value], value))[0]
        cwes = Counter(cwe for item in members for cwe in item.cwe_ids)
        primary_cwe = (
            sorted(cwes, key=lambda value: (-cwes[value], value))[0]
            if cwes
            else "UNRESOLVED"
        )
        strata.setdefault((primary_source, primary_cwe), []).append(cluster_id)

    discover: set[str] = set()
    for stratum, cluster_ids in sorted(strata.items()):
        shuffled = sorted(cluster_ids)
        random.Random(_derived_seed(seed, ratio, stratum)).shuffle(shuffled)
        discover_count = round(len(shuffled) * ratio)
        if len(shuffled) > 1:
            discover_count = min(max(discover_count, 1), len(shuffled) - 1)
        discover.update(shuffled[:discover_count])

    assignments = tuple(
        SplitAssignment(
            record_key=record.record_key,
            cluster_id=record.cluster_id,
            split=(
                "UNRESOLVED"
                if record.cluster_id in unresolved
                else "discover"
                if record.cluster_id in discover
                else "confirm"
            ),
        )
        for record in records
    )
    summary: dict[str, object] = {
        "records": len(records),
        "independent_clusters": len(independent),
        "unresolved_clusters": len(unresolved),
        "discover_clusters": len(discover),
        "confirm_clusters": len(independent) - len(discover),
        "counts_by_source": _counts(records, "source_id"),
        "counts_by_language": _counts(records, "language"),
        "counts_by_cwe": _counts(records, "cwe_ids"),
        "pipeline_floor": minimum_cluster_floor,
        "pipeline_floor_met": len(independent) >= minimum_cluster_floor,
    }
    return SplitSimulation(
        discover_ratio=ratio,
        seed=seed,
        version=SPLIT_VERSION,
        assignments=assignments,
        independent_cluster_ids=tuple(independent),
        unresolved_cluster_ids=tuple(sorted(unresolved)),
        summary=summary,
    )


def simulate_cluster_splits(
    records: list[SplitRecord],
    *,
    ratios: tuple[float, ...],
    seed: int,
    minimum_cluster_floor: int = 20,
) -> SplitSimulationResult:
    if minimum_cluster_floor < 1:
        raise ValueError("minimum cluster floor must be positive")
    ordered = sorted(records, key=lambda item: item.record_key)
    if len({item.record_key for item in ordered}) != len(ordered):
        raise ValueError("split record keys must be unique")
    if len(set(ratios)) != len(ratios):
        raise ValueError("split ratios must be unique")
    return SplitSimulationResult(
        simulations=tuple(
            _one_simulation(ordered, ratio, seed, minimum_cluster_floor)
            for ratio in ratios
        )
    )

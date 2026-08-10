from __future__ import annotations

from dataclasses import replace

from secaware.dataset_audit.schema import FunctionalState, NeutralityState
from secaware.dataset_audit.splits import SplitRecord, simulate_cluster_splits


def _records(count: int = 24) -> list[SplitRecord]:
    return [
        SplitRecord(
            record_key=f"r{index}",
            cluster_id=f"c{index // 2}",
            source_id="alpha" if index % 4 else "beta",
            language="python",
            cwe_ids=("CWE-89",) if index % 3 else ("CWE-78",),
            neutrality=NeutralityState.CANDIDATE_NEUTRAL,
            functional_state=FunctionalState.PRESENT_UNVALIDATED,
            independence_resolved=True,
        )
        for index in range(count)
    ]


def test_all_frozen_ratios_are_deterministic_and_cluster_disjoint() -> None:
    records = _records(48)
    first = simulate_cluster_splits(records, ratios=(0.5, 0.6, 0.7), seed=20260810)
    second = simulate_cluster_splits(list(reversed(records)), ratios=(0.5, 0.6, 0.7), seed=20260810)

    assert first == second
    assert [item.discover_ratio for item in first.simulations] == [0.5, 0.6, 0.7]
    for simulation in first.simulations:
        cluster_splits: dict[str, set[str]] = {}
        for assignment in simulation.assignments:
            cluster_splits.setdefault(assignment.cluster_id, set()).add(assignment.split)
        assert all(len(splits) == 1 for splits in cluster_splits.values())


def test_unresolved_clusters_are_reported_and_not_counted_independent() -> None:
    records = _records(6)
    records[0] = replace(records[0], independence_resolved=False)

    result = simulate_cluster_splits(records, ratios=(0.5,), seed=1)
    simulation = result.simulations[0]

    unresolved_cluster = records[0].cluster_id
    assert unresolved_cluster in simulation.unresolved_cluster_ids
    assert all(
        assignment.split == "UNRESOLVED"
        for assignment in simulation.assignments
        if assignment.cluster_id == unresolved_cluster
    )
    assert unresolved_cluster not in simulation.independent_cluster_ids


def test_summary_reports_strata_and_pipeline_floor_without_power_claim() -> None:
    result = simulate_cluster_splits(
        [
            SplitRecord(
                record_key=f"r{i}",
                cluster_id=f"c{i}",
                source_id="alpha",
                language="python",
                cwe_ids=("CWE-89",),
                neutrality=NeutralityState.CANDIDATE_NEUTRAL,
                functional_state=FunctionalState.PRESENT_UNVALIDATED,
                independence_resolved=True,
            )
            for i in range(21)
        ],
        ratios=(0.5,),
        seed=3,
        minimum_cluster_floor=20,
    )

    summary = result.simulations[0].summary
    assert summary["counts_by_source"] == {"alpha": 21}
    assert summary["counts_by_language"] == {"python": 21}
    assert summary["counts_by_cwe"] == {"CWE-89": 21}
    assert summary["pipeline_floor_met"] is True
    assert "adequately_powered" not in summary

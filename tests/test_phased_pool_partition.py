from __future__ import annotations

from hashlib import sha256

import pytest
from pydantic import ValidationError

from secaware.phased_exploration.pools import (
    ContractStatus,
    EvidencePool,
    PoolPartitionManifest,
    PoolTaskRecord,
)


def _sha(label: str) -> str:
    return sha256(label.encode()).hexdigest()


def _task(
    suffix: str,
    *,
    cluster: str | None = None,
    pool: EvidencePool = EvidencePool.CANARY,
    exposed: bool = False,
) -> PoolTaskRecord:
    return PoolTaskRecord.from_content(
        pool=pool,
        semantic_task_cluster_id=cluster or f"cluster-{suffix}",
        task_instance_id=f"task-{suffix}",
        source_id="fixture-source",
        source_record_id=f"record-{suffix}",
        prompt_sha256=_sha(f"prompt-{suffix}"),
        cwe_id="CWE-78",
        archetype_id="argument-vector-subprocess",
        template_family_id=f"template-{cluster or suffix}",
        functional_contract_status=ContractStatus.EXECUTABLE_VALIDATED,
        security_contract_status=ContractStatus.EXECUTABLE_VALIDATED,
        legacy_outcome_exposed=exposed,
        exposure_artifact_sha256=(_sha("legacy-outcome"),) if exposed else (),
    )


def _manifest(*tasks: PoolTaskRecord) -> PoolPartitionManifest:
    return PoolPartitionManifest.from_content(
        partition_version="phase-partition-v1",
        semantic_cluster_policy_sha256=_sha("cluster-policy"),
        source_inventory_sha256=_sha("source-inventory"),
        tasks=tasks,
    )


def test_exact_eight_pool_vocabulary_and_claim_boundary() -> None:
    assert {item.value for item in EvidencePool} == {
        "D_GOLD",
        "D_CANARY",
        "D_SENTINEL",
        "D_DEV_DISCOVERY",
        "D_DEV_CONFIRM",
        "D_FORMAL_DISCOVERY",
        "D_FORMAL_CONFIRM",
        "D_REPLICATION",
    }
    manifest = _manifest(_task("one"))
    assert manifest.pool_is_claim_eligible(EvidencePool.FORMAL_CONFIRM)
    assert not manifest.pool_is_claim_eligible(EvidencePool.SENTINEL)
    assert manifest.counts_by_pool()["D_CANARY"] == 1
    assert manifest.counts_by_pool()["D_FORMAL_CONFIRM"] == 0


def test_multiple_task_instances_of_one_cluster_must_stay_in_one_pool() -> None:
    first = _task("one", cluster="cluster-shared")
    second = _task("two", cluster="cluster-shared")
    # A semantic cluster may contain multiple task instances, but they remain one pool unit.
    manifest = _manifest(first, second)
    assert len(manifest.tasks) == 2

    moved_payload = second.model_dump(mode="python")
    moved_payload["pool"] = EvidencePool.SENTINEL
    moved_payload["membership_id"] = "pool_task_" + "0" * 64
    with pytest.raises(ValidationError):
        PoolTaskRecord.model_validate(moved_payload)

    moved = _task("two-moved", cluster="cluster-shared", pool=EvidencePool.SENTINEL)
    with pytest.raises(ValidationError):
        _manifest(first, moved)


def test_exposed_material_is_limited_to_gold_or_canary() -> None:
    assert _task("canary", exposed=True).legacy_outcome_exposed
    assert _task("gold", pool=EvidencePool.GOLD, exposed=True).legacy_outcome_exposed
    for pool in (
        EvidencePool.SENTINEL,
        EvidencePool.DEV_DISCOVERY,
        EvidencePool.DEV_CONFIRM,
        EvidencePool.FORMAL_DISCOVERY,
        EvidencePool.FORMAL_CONFIRM,
        EvidencePool.REPLICATION,
    ):
        with pytest.raises(ValidationError):
            _task(pool.value, pool=pool, exposed=True)


def test_exposure_provenance_and_task_identity_fail_closed() -> None:
    payload = _task("one").model_dump(mode="python")
    payload["legacy_outcome_exposed"] = True
    with pytest.raises(ValidationError):
        PoolTaskRecord.model_validate(payload)

    first = _task("duplicate")
    with pytest.raises(ValidationError):
        _manifest(first, first)


def test_manifest_is_canonical_and_policy_mutation_changes_identity() -> None:
    first = _task("one")
    second = _task("two", pool=EvidencePool.GOLD)
    left = _manifest(first, second)
    right = _manifest(second, first)
    assert left == right
    assert left.manifest_id == right.manifest_id

    changed = PoolPartitionManifest.from_content(
        partition_version="phase-partition-v1",
        semantic_cluster_policy_sha256=_sha("different-cluster-policy"),
        source_inventory_sha256=_sha("source-inventory"),
        tasks=(first, second),
    )
    assert changed.manifest_id != left.manifest_id

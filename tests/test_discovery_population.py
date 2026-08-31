from dataclasses import replace

import pytest

from prompt_mechanism_study.prioritization import (
    CoverageAcquisitionMode,
    CoverageAcquisitionRequest,
    CoverageCellSupport,
    CoverageCensusPhase,
    CoverageTarget,
    CoverageTargetProfile,
    D0ExposureCategory,
    D0TaskDisposition,
    DiscoveryCoverageCensus,
    DiscoveryPopulationLineage,
    DiscoveryPopulationStatus,
    DiscoverySupplementationPlan,
    DiscoverySupplementationReceipt,
    PairCoverageCellSupport,
    PairCoverageTarget,
    SupplementationDecision,
)
from prompt_mechanism_study.records import content_hash


pytestmark = pytest.mark.reviewer


def _coverage_profile(
    mode: CoverageAcquisitionMode,
    maximum_new_task_units: int,
) -> tuple[CoverageTargetProfile, CoverageTarget, PairCoverageTarget]:
    target = CoverageTarget("context.xml", "feature.xxe-control", 2, 2, 1)
    pair_target = PairCoverageTarget(
        "pair-policy.xml",
        "context.xml",
        ("feature.first", "feature.second"),
        2,
        1,
    )
    return (
        CoverageTargetProfile(
            protocol_id="phase-context-policy-v3",
            schema_version="3.0",
            representation_profile_id="prompt-tsg-profile-v3",
            representation_qualification_sha256=content_hash(
                "accepted-representation-qualification"
            ),
            catalog_sha256=content_hash("frozen-catalog"),
            support_profile_sha256=content_hash("accepted-support-profile"),
            common_candidate_universe_sha256=content_hash(
                "common-candidate-universe"
            ),
            targets=(target,),
            pair_targets=(pair_target,),
            permitted_source_families=("independent-public-source",),
            acquisition_mode=mode,
            maximum_source_records=maximum_new_task_units * 2,
            maximum_new_task_units=maximum_new_task_units,
            maximum_review_task_units=maximum_new_task_units * 2,
            maximum_task_units_per_lineage=1,
            minimum_source_lineage_diversity=1,
            minimum_fillable_atomic_slots=1,
            minimum_fillable_pair_slots=1,
        ),
        target,
        pair_target,
    )


def _census(
    profile: CoverageTargetProfile,
    target: CoverageTarget,
    pair_target: PairCoverageTarget,
    phase: CoverageCensusPhase,
    task_unit_ids: tuple[str, ...],
    population_sha256: str,
    fillable_pair_candidates: int = 1,
) -> DiscoveryCoverageCensus:
    return DiscoveryCoverageCensus(
        profile.profile_id,
        "data-role-manifest-test",
        "task-population-manifest-test",
        profile.representation_profile_id,
        profile.catalog_sha256,
        phase,
        population_sha256,
        profile.representation_qualification_sha256,
        task_unit_ids,
        (
            CoverageCellSupport(
                target.target_id,
                len(task_unit_ids),
                2,
                2,
                ("lineage-a",),
                ("lineage-a",),
            ),
        ),
        (
            PairCoverageCellSupport(
                pair_target.target_id,
                (("00", 2), ("01", 2), ("10", 2), ("11", 2)),
                tuple(
                    (cell, ("lineage-a",))
                    for cell in ("00", "01", "10", "11")
                ),
            ),
        ),
        1,
        fillable_pair_candidates,
        1,
        fillable_pair_candidates,
    )


def test_d0_no_supplement_lineage_is_selector_blind_and_single_round() -> None:
    profile, target, pair_target = _coverage_profile(
        CoverageAcquisitionMode.CONTEXT_FIRST,
        0,
    )
    population = content_hash(("task-a", "task-b"))
    pre = _census(
        profile,
        target,
        pair_target,
        CoverageCensusPhase.PRE_SUPPLEMENT,
        ("task-a", "task-b"),
        population,
    )
    plan = DiscoverySupplementationPlan(
        profile.profile_id,
        pre.census_id,
        population,
        SupplementationDecision.NOT_REQUESTED,
        (),
        ("task-a",),
        content_hash("future-evaluation-reservation-v1"),
        (),
        (),
        content_hash("near-duplicate-rule"),
        content_hash("exposure-policy"),
        content_hash("role-allocation-rule"),
        "0" * 40,
        False,
        0,
    )
    post = _census(
        profile,
        target,
        pair_target,
        CoverageCensusPhase.POST_SUPPLEMENT,
        ("task-a", "task-b"),
        population,
    )
    lineage = DiscoveryPopulationLineage(
        profile,
        pre,
        plan,
        None,
        post,
        population,
        DiscoveryPopulationStatus.READY_WITHOUT_SUPPLEMENTATION,
    )

    assert lineage.accepted_population_manifest_sha256 == population
    assert lineage.formal_discovery_ready is True
    assert plan.prohibited_inputs == (
        "FCI_OR_PAG_EVIDENCE",
        "NATURAL_OUTCOMES",
        "PAIR_RELATION_SUPPORT",
        "RD_SCORES",
        "SELECTOR_MEMBERSHIP_OR_RANK",
    )
    with pytest.raises(ValueError, match="exactly one"):
        replace(profile, maximum_rounds=2)
    with pytest.raises(ValueError, match="cannot read outcomes"):
        replace(pre, outcomes_read=True)
    with pytest.raises(ValueError, match="cannot be weakened"):
        replace(plan, prohibited_inputs=plan.prohibited_inputs[:-1])

    blocked_pre = replace(
        pre,
        fillable_pair_candidates=0,
        fold_feasible_pair_candidates=0,
    )
    blocked_post = replace(
        post,
        fillable_pair_candidates=0,
        fold_feasible_pair_candidates=0,
    )
    blocked_plan = replace(plan, pre_census_id=blocked_pre.census_id)
    blocked = DiscoveryPopulationLineage(
        profile,
        blocked_pre,
        blocked_plan,
        None,
        blocked_post,
        population,
        DiscoveryPopulationStatus.COVERAGE_BLOCKED,
    )
    assert blocked.formal_discovery_ready is False


def test_d0_accepts_one_bounded_natural_additive_supplement_only() -> None:
    profile, target, pair_target = _coverage_profile(
        CoverageAcquisitionMode.STATE_TARGETED,
        2,
    )
    pre_population = content_hash(("task-a", "task-b"))
    post_population = content_hash(("task-a", "task-b", "task-c", "task-d"))
    pre = _census(
        profile,
        target,
        pair_target,
        CoverageCensusPhase.PRE_SUPPLEMENT,
        ("task-a", "task-b"),
        pre_population,
        0,
    )
    plan = DiscoverySupplementationPlan(
        profile.profile_id,
        pre.census_id,
        pre_population,
        SupplementationDecision.PLANNED,
        (
            CoverageAcquisitionRequest(
                pair_target.target_id,
                0,
                0,
                0,
                (("11", 2),),
            ),
        ),
        (),
        content_hash("future-evaluation-reservation-v1"),
        (content_hash("source-snapshot"),),
        (content_hash("state-targeted-retrieval-rule"),),
        content_hash("near-duplicate-rule"),
        content_hash("exposure-policy"),
        content_hash("role-allocation-rule"),
        "0" * 40,
        True,
        1,
    )
    receipt = DiscoverySupplementationReceipt(
        plan.supplementation_plan_id,
        1,
        pre_population,
        post_population,
        3,
        2,
        1,
        ("task-c", "task-d"),
        (
            D0TaskDisposition(
                "source-c",
                "task-c",
                "near-c",
                "lineage-c",
                True,
                "ACCEPTED_DISCOVERY",
                (D0ExposureCategory.SOURCE_CURATION_VIEWED,),
            ),
            D0TaskDisposition(
                "source-d",
                "task-d",
                "near-d",
                "lineage-d",
                True,
                "ACCEPTED_DISCOVERY",
                (D0ExposureCategory.SOURCE_CURATION_VIEWED,),
            ),
            D0TaskDisposition(
                "source-e",
                "task-e",
                "near-e",
                "lineage-e",
                False,
                "REJECTED_QUALITY",
                (D0ExposureCategory.SOURCE_CURATION_VIEWED,),
            ),
        ),
        content_hash("source-provenance"),
        content_hash("deduplication-manifest"),
        content_hash("contract-quality-readiness"),
        content_hash("exposure-records"),
        content_hash("data-role-manifest"),
        "1" * 40,
        "PASS",
    )
    post = _census(
        profile,
        target,
        pair_target,
        CoverageCensusPhase.POST_SUPPLEMENT,
        ("task-a", "task-b", "task-c", "task-d"),
        post_population,
    )
    lineage = DiscoveryPopulationLineage(
        profile,
        pre,
        plan,
        receipt,
        post,
        post_population,
        DiscoveryPopulationStatus.READY_AFTER_ONE_ROUND,
    )

    assert lineage.receipt is receipt
    with pytest.raises(ValueError, match="single allowed round"):
        replace(receipt, round_index=2)
    with pytest.raises(ValueError, match="prohibited synthetic"):
        replace(receipt, paraphrases_or_interventions_used=True)
    with pytest.raises(ValueError, match="acquisition ceiling"):
        replace(
            lineage,
            plan=replace(
                plan,
                requests=(
                    CoverageAcquisitionRequest(
                        pair_target.target_id,
                        0,
                        0,
                        0,
                        (("11", 3),),
                    ),
                ),
            ),
        )

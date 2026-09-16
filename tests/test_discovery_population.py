from dataclasses import replace
import pytest
from prompt_mechanism_study.discovery_population import (
    CoverageAcquisitionMode,
    CoverageAcquisitionRequest,
    CoverageCellSupport,
    CoverageCensusPhase,
    CoverageTarget,
    CoverageTargetProfile,
    DiscoveryCoverageCensus,
    DiscoveryPopulationLineage,
    DiscoveryPopulationStatus,
    DiscoverySupplementationPlan,
    SupplementationDecision,
    count_context_coverage,
    plan_context_acquisitions,
)
from prompt_mechanism_study.records import content_hash


def _coverage_profile(
    mode: CoverageAcquisitionMode,
    maximum_new_task_units: int,
) -> tuple[CoverageTargetProfile, CoverageTarget]:
    target = CoverageTarget("context.xml", 4 if maximum_new_task_units else 2)
    return (
        CoverageTargetProfile(
            protocol_id="phase-context-policy-v3",
            schema_version="4.0",
            representation_profile_id="prompt-tsg-profile-v3",
            representation_qualification_sha256=content_hash(
                "accepted-representation-qualification"
            ),
            catalog_sha256=content_hash("frozen-catalog"),

            targets=(target,),

            permitted_source_families=("independent-public-source",),
            acquisition_mode=mode,
            maximum_source_records=maximum_new_task_units * 2,
            maximum_new_task_units=maximum_new_task_units,
            maximum_review_task_units=maximum_new_task_units * 2,
            maximum_task_units_per_lineage=1,
            minimum_source_lineage_diversity=1,


        ),
        target,
    )


def _census(
    profile: CoverageTargetProfile,
    target: CoverageTarget,
    phase: CoverageCensusPhase,
    task_unit_ids: tuple[str, ...],
    population_sha256: str,
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
        (CoverageCellSupport(target.target_id, len(task_unit_ids)),),
    )


def test_d0_no_supplement_lineage_is_selector_blind_and_single_round() -> None:
    profile, target = _coverage_profile(
        CoverageAcquisitionMode.CONTEXT_FIRST,
        0,
    )
    population = content_hash(("task-a", "task-b"))
    pre = _census(
        profile,
        target,
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
        "FEATURE_STATES_OR_PAIR_CELLS",
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
        cells=(CoverageCellSupport(target.target_id, 1),),
    )
    blocked_post = replace(
        post,
        cells=(CoverageCellSupport(target.target_id, 1),),
    )
    blocked_plan = replace(plan, pre_census_id=blocked_pre.census_id)
    blocked = DiscoveryPopulationLineage(
        profile,
        blocked_pre,
        blocked_plan,
        None,
        blocked_post,
        population,
        DiscoveryPopulationStatus.COVERAGE_GAPS_RETAINED,
    )
    assert blocked.formal_discovery_ready is True  # Remaining context gaps do not veto covered candidates.


def test_d0_counts_tasks_once_retains_unknown_and_cannot_receive_feature_states():
    profile, target = _coverage_profile(CoverageAcquisitionMode.CONTEXT_FIRST, 2)
    row = {"task_unit_id": "a", "context_states": {"context.xml": "present"}}
    rows = (row, row, {"task_unit_id": "b", "context_states": {"context.xml": "unresolved"}})
    cells = count_context_coverage(profile, rows)
    assert cells == (CoverageCellSupport(target.target_id, 1, 1),)
    census = replace(_census(profile, target, CoverageCensusPhase.PRE_SUPPLEMENT,
                            ("a", "b"), content_hash("population")), cells=cells)
    assert plan_context_acquisitions(profile, census) == (CoverageAcquisitionRequest(target.target_id, 2),)
    with pytest.raises(ValueError, match="only task identity"):
        count_context_coverage(profile, ({**row, "feature_states": {"safety": "absent"}},))
    with pytest.raises(TypeError):
        replace(census, fillable_pair_candidates=0)
    with pytest.raises(ValueError):
        CoverageAcquisitionMode("STATE_TARGETED")

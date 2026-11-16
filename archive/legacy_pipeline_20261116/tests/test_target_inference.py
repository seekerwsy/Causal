"""Schema-3 assigned-arm ITT, fixed-K reporting, and verifier invariants."""

from __future__ import annotations
import copy
import json
import random
from dataclasses import asdict, replace
from types import SimpleNamespace
import pytest
from prompt_mechanism_study.experiment.inference import (
    ConfirmatoryEffectStatus,
    ContextAnalysisPlan,
    EvidenceLevel,
    TargetFamilyStatus,
    TargetITTPlan,
    TargetTaskUnitContribution,
    _target_family_bootstrap,
    _target_resampled_point_standard_error,
    build_target_selector_yields,
    classify_confirmatory_interval,
    estimate_target_itt,
    freeze_assigned_arm_evidence,
)
from prompt_mechanism_study.measurement.evaluate import InfrastructureFailure
from prompt_mechanism_study.measurement.evaluate import MeasurementLedger, measure_generated_code
from prompt_mechanism_study.experiment.outcomes import Outcome, derive_outcomes
from prompt_mechanism_study.discovery.prioritization import (
    BridgeStatus,
    FixedSlotSource,
    PolicyTrack,
    SelectorSlot,
    SlotStatus,
    freeze_confirmation_dispatch,
    freeze_fixed_slot_ledger,
)
from prompt_mechanism_study.experiment.randomization import (
    ATOMIC_CONFIRMATORY_ARMS,
    AssignedArmITTRecord,
)
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.tsg.representation import ModelBoundCandidateRecord
from prompt_mechanism_study.experiment.reporting import build_target_rq_tables
from prompt_mechanism_study.verification import (
    verify_target_rq_tables,
    verify_target_shared_evidence,
)
from prompt_mechanism_study.verification.reporting import (
    _replay_execution_measurements,
)
from prompt_mechanism_study.measurement.security_profiles import (
    security_profile_producer_sha256,
)


def test_realization_mixture_keeps_frozen_weights_under_unequal_support() -> None:
    weight = 0.25
    ledger, plan = _target_v3_fixture()
    old_outcomes = {item.assignment_id: item for item in ledger.outcomes}
    assignments, outcomes = ([], [])
    for old in ledger.assignments:
        index = int(old.task_unit_id.rsplit("-", 1)[1])
        if index >= 8:
            continue
        first = index < 6
        new = replace(
            old,
            realization_id="r1" if first else "r2",
            realization_weight=weight if first else 1 - weight,
        )
        secure = int(first and old.arm.value in {"atomic_target"})
        assignments.append(new)
        outcomes.append(
            replace(
                old_outcomes[old.assignment_id],
                assignment_id=new.assignment_id,
                secure_yield=secure,
                oracle_evaluable=1,
                latent_secure_upper=secure,
                functionality=int(first),
                joint=secure,
                latent_joint_upper=secure,
            )
        )
    result = estimate_target_itt(
        freeze_assigned_arm_evidence(ledger.dispatch, assignments, outcomes), plan
    )
    for family in result.families:
        effect = family.estimates[0]
        assert effect.point == pytest.approx(weight)
        assert effect.latent_lower == pytest.approx(weight)
        assert effect.latent_upper == pytest.approx(weight)
        for arm in effect.arm_summaries:
            assert arm.code_validity == pytest.approx(1)
            assert arm.functionality_yield == pytest.approx(weight)
            if arm.arm.value in {"atomic_target"}:
                assert arm.secure_yield == pytest.approx(weight)
                assert arm.joint_success_yield == pytest.approx(weight)
    verify_target_shared_evidence(result, build_target_selector_yields(result))


def test_missing_realization_is_non_evaluable_without_weight_renormalization() -> None:
    ledger, plan = _target_v3_fixture()
    outcomes_by_id = {item.assignment_id: item for item in ledger.outcomes}
    assignments = tuple(replace(item, realization_weight=0.5) for item in ledger.assignments)
    outcomes = tuple(replace(outcomes_by_id[old.assignment_id], assignment_id=new.assignment_id)
                     for old, new in zip(ledger.assignments, assignments))
    result = estimate_target_itt(freeze_assigned_arm_evidence(ledger.dispatch, assignments, outcomes), plan)
    for family in result.families:
        assert family.status is TargetFamilyStatus.INSUFFICIENT_SUPPORT
        assert family.estimates[0].point is None
        assert "incomplete_realization_support" in family.estimates[0].reasons
    verify_target_shared_evidence(result, build_target_selector_yields(result))


def test_joint_bootstrap_applies_frozen_minimum_to_every_effect() -> None:
    _, plan = _target_v3_fixture()
    plan = replace(plan, bootstrap_seed=7, bootstrap_draws=1000)
    works = tuple(
        (
            SimpleNamespace(
                track=PolicyTrack.ATOMIC,
                point=0.5,
                stratum_weights=(("r1", "s", 1.0),),
                contributions=tuple(
                    (
                        TargetTaskUnitContribution(
                            f"{prefix}{i}", "s", float(i - 1), float(i - 1), float(i - 1), "r1", 1.0
                        )
                        for i in range(4)
                    )
                ),
            )
            for prefix in ("a", "b")
        )
    )
    assert _target_resampled_point_standard_error(works[0], {"s": ("a0", "a1", "a2")}, plan) is None
    population = tuple((f"{prefix}{i}" for prefix in ("a", "b") for i in range(4)))
    rng = random.Random(
        int(
            content_hash(
                {
                    "domain": "target_max_t_task_unit_bootstrap_v1",
                    "seed": 7,
                    "track": PolicyTrack.ATOMIC,
                    "plan_id": plan.target_itt_plan_id,
                }
            )[-16:],
            16,
        )
    )
    expected_valid = 0
    old_minimum_valid = 0
    for _ in range(1000):
        draw = [population[rng.randrange(8)] for _ in range(8)]
        cells = [
            [int(unit[1:]) for unit in draw if unit.startswith(prefix)] for prefix in ("a", "b")
        ]
        if all((len(values) >= 2 and len(set(values)) >= 2 for values in cells)):
            old_minimum_valid += 1
        if all(len(values) >= 4 for values in cells):
            expected_valid += 1
    maxima, invalid = _target_family_bootstrap(PolicyTrack.ATOMIC, works, plan)
    assert len(maxima) == expected_valid
    assert invalid == 1000 - expected_valid
    assert expected_valid < 800 <= old_minimum_valid
    assert any(value == float('inf') for value in maxima)


def test_draft_result_cannot_grant_itself_formal_authorization():
    from prompt_mechanism_study.experiment.reporting import build_target_rq_tables
    from prompt_mechanism_study.experiment.inference import EvidenceLevel
    ledger, plan = _target_v3_fixture()
    evidence = estimate_target_itt(ledger, plan, evidence_level=EvidenceLevel.EXECUTED)
    yields = build_target_selector_yields(evidence)
    with pytest.raises(ValueError, match="SPECIFIED_DRAFT"):
        build_target_rq_tables(evidence, yields)


@pytest.mark.parametrize("code,source_status,verdict", [
    # Exercise each verdict and source disposition once; validity is a separate boundary.
    pytest.param("import requests\nrequests.get('https://example.test')", source, verdict,
                 id=f"valid-{source}-{verdict}")
    for source, verdict in (("insufficient", "pass"), ("sufficient", "fail"), ("defect", "unknown"))
] + [
    # Missing or invalid code never reaches the judge; its verdict is unused.
    pytest.param("", "sufficient", "unknown", id="empty-no-judge"),
    pytest.param("def broken(:", "sufficient", "unknown", id="invalid-no-judge"),
])
def test_execution_verifier_rebuilds_raw_measurements_and_rejects_tampering(code, source_status, verdict) -> None:
    ledger, _ = _target_v3_fixture()
    assignment = replace(ledger.assignments[0], variant_sha256=content_hash("frozen prompt"))
    request = {"model_id": assignment.model_id, "arm": assignment.arm.value,
               "task_unit_id": assignment.task_unit_id, "task_instance_id": assignment.task_instance_id,
               "provider_seed": assignment.provider_seed, "prompt": "frozen prompt"}
    functional_contract = {"requirements": [{"requirement_id": "r1", "criterion": "Fetch the URL"}],
                           "environment_dependencies": [], "language": "python",
                           "review": {"source_specification_disposition": source_status}}
    functional_evaluator = {"model_id": assignment.model_id}
    responses = iter([json.dumps({"code": code}).encode(),
                      json.dumps({"verdict": verdict, "evidence_lines": [1],
                                  "reason": "Controlled response tests verdict propagation, not judge accuracy."}).encode()])
    measured, raw = measure_generated_code(
        assignment_id=assignment.assignment_id, generation_request=request,
        generation_evaluator={"model_id": assignment.model_id}, generation_prompt="frozen prompt",
        source_task_prompt="Fetch the URL", functional_contract=functional_contract,
        functional_evaluator=functional_evaluator, functional_prompt="Review functionality",
        security_profile_id="python.cwe295.tls_certificate_validation.v1",
        complete=lambda *_: next(responses),
    )
    outcomes = derive_outcomes(MeasurementLedger("test", "test", "test", (measured,)))
    evidence = SimpleNamespace(ledger=SimpleNamespace(
        assignments=(assignment,), outcomes=outcomes, infrastructure_failures=(),
    ))
    contract = {"task_contracts": {assignment.task_instance_id: {
        "functional_contract": functional_contract, "functional_evaluator": functional_evaluator,
        "source_task_prompt": "Fetch the URL", "security_profile_id": "python.cwe295.tls_certificate_validation.v1",
        "security_producer_sha256": security_profile_producer_sha256(),
    }}}
    raw.update(assignment_id=assignment.assignment_id, measurement=asdict(measured),
               functional_evaluator=functional_evaluator)
    # Serialize as an actual persisted JSON payload; this remains a test fixture.
    provider_ledger = json.loads(json.dumps({"records": [raw]}))
    assert _replay_execution_measurements(evidence, contract, provider_ledger)["assignments"] == 1
    # Binding/tamper checks need one valid record; the verdict/validity cases below stay distinct.
    if source_status == "insufficient":
        for field, value in (("generation_response", None), ("code", "tampered code"),
                             ("generation_request", {**request, "model_id": "wrong-model"}),
                             ("generation_request", {**request, "provider_seed": 7}),
                             ("measurement", None)):
            tampered = copy.deepcopy(provider_ledger)
            tampered["records"][0][field] = value
            with pytest.raises((TypeError, ValueError)):
                _replay_execution_measurements(evidence, contract, tampered)
        with pytest.raises(ValueError, match="every assignment"):
            _replay_execution_measurements(evidence, contract, {"records": []})
    if code.startswith("import"):
        tampered = copy.deepcopy(provider_ledger)
        tampered["records"][0]["functional_response"] = None
        with pytest.raises(ValueError, match="functional response"):
            _replay_execution_measurements(evidence, contract, tampered)
        assert outcomes[0].secure_yield == 1
        assert outcomes[0].functionality == outcomes[0].joint == {"pass": 1, "fail": 0, "unknown": None}[verdict]
        assert provider_ledger["records"][0]["functional_request"] is not None
        tampered = copy.deepcopy(provider_ledger)
        tampered["records"][0]["functional_validated"]["status"] = "fail" if verdict == "pass" else "pass"
        with pytest.raises(ValueError, match="labels/digests"):
            _replay_execution_measurements(evidence, contract, tampered)
        wrong = replace(outcomes[0], secure_yield=0, latent_secure_upper=0, joint=0, latent_joint_upper=0)
        evidence.ledger.outcomes = (wrong,)
        with pytest.raises(ValueError, match="outcome failed"):
            _replay_execution_measurements(evidence, contract, provider_ledger)
    else:
        assert provider_ledger["records"][0]["functional_request"] is None
        assert outcomes[0].code_valid == 0
        assert outcomes[0].secure_yield == outcomes[0].joint == 0


def _target_v3_fixture(policy_keys=("atomic-policy-v3",)):
    records = tuple(ModelBoundCandidateRecord(key, "model.atomic", "phase-context-policy-v3", "3.0")
                    for key in sorted(policy_keys))
    sources = tuple(FixedSlotSource(PolicyTrack.ATOMIC, selector, "model.atomic", "atomic-universe-v3",
        tuple(SelectorSlot(i + 1, SlotStatus.FILLED, record.policy_key, None) for i, record in enumerate(records)),
        records) for selector in ("atomic_full", "atomic_rd_only"))
    ledger = freeze_fixed_slot_ledger("phase-context-policy-v3", "3.0", sources)
    dispatch = freeze_confirmation_dispatch(ledger, {r.candidate_record_id: "atomic-protocol-record-v3" for r in records})
    dispatch_by_candidate = {item.candidate_record_id: item for item in dispatch.records}
    assignments = []
    outcomes = []
    for candidate in ledger.selected_candidates:
        track, arms = PolicyTrack.ATOMIC, ATOMIC_CONFIRMATORY_ARMS
        dispatched = dispatch_by_candidate[candidate.candidate_record_id]
        for index in range(12):
            for request_slot, arm in enumerate(arms):
                assignment = AssignedArmITTRecord(
                    candidate.candidate_record_id,
                    candidate.effect_coordinate.effect_coordinate_id,
                    candidate.policy_key,
                    candidate.discovery_model_id,
                    track,
                    f"{track.value}-unit-{index:02d}",
                    f"{track.value}-task-{index:02d}",
                    "synthetic-stratum",
                    f"{track.value}-realization-v1",
                    f"{track.value}-bundle-{index:02d}",
                    dispatched.protocol_record_id,
                    request_slot,
                    arm,
                    1.0,
                    1.0,
                    content_hash((track.value, index, arm.value)),
                )
                assignments.append(assignment)
                secure = (
                    index < 10
                    if arm.value == "atomic_target"
                    else index < 1 if arm.value == "atomic_noop" else index % 3 == 0
                )
                unknown = arm.value == "atomic_target" and index == 11
                outcomes.append(
                    Outcome(
                        assignment.assignment_id,
                        1,
                        0 if unknown else 1,
                        int(secure and (not unknown)),
                        int(secure or unknown),
                        1,
                        None if unknown else int(secure),
                        int(secure or unknown),
                        None,
                    )
                )
    evidence = freeze_assigned_arm_evidence(dispatch, assignments, outcomes)
    plan = TargetITTPlan(20260831, 300, 0.05, 4, 0.8, 0.05, 0.5)
    return (evidence, plan)


def test_shared_itt_reporting_and_independent_replay() -> None:
    evidence, plan = _target_v3_fixture()
    result = estimate_target_itt(evidence, plan, evidence_level=EvidenceLevel.TESTED)
    yields = build_target_selector_yields(result)
    verification = verify_target_shared_evidence(result, yields)
    assert tuple((item.status for item in result.families)) == (TargetFamilyStatus.EVALUABLE,)
    estimates = tuple((item for family in result.families for item in family.estimates))
    assert len(estimates) == 1
    assert all((item.status is ConfirmatoryEffectStatus.POSITIVE_MEANINGFUL for item in estimates))
    assert all((item.assignments == 48 and item.task_units == 12 for item in estimates))
    atomic = next((item for item in estimates if item.track is PolicyTrack.ATOMIC))
    assert atomic.point == pytest.approx(0.75)
    assert atomic.latent_upper > atomic.point
    target_summary = atomic.arm_summaries[0]
    assert target_summary.oracle_unknown_valid_assignments == 1
    assert len(yields.slots) == 2
    assert all((item.meaningful_yield == 1 for item in yields.slots))
    assert all((item.top_k == 1 and item.meaningful_yield_at_k == 1 for item in yields.selectors))
    assert verification["status"] == "TARGET_SHARED_EVIDENCE_VERIFIED"

    # Report the same frozen estimate; keep fixed slots and claim limits.
    report = build_target_rq_tables(result, yields)
    verification = verify_target_rq_tables(result, yields, report)
    assert report["report_status"] == "NON_CLAIM_TEST_ARTIFACT"
    assert report["scientific_claim_allowed"] is False
    assert report["context_analysis_status"] == "BLOCKED_NO_FROZEN_CONTEXT_RULE"
    assert report["context_modifier_rows"] == []
    assert len(report["rq1_selector_rows"]) == 2
    assert len(report["rq2_full_minus_ablation_rows"]) == 1
    assert all(
        (
            row["top_k"] == 1 and row["meaningful_yield_at_k"] == 1.0
            for row in report["rq1_selector_rows"]
        )
    )
    assert all(
        (
            row["full_minus_ablation_yield_at_k"] == 0.0
            and row["comparison_semantics"] == "descriptive_fixed_discovery_split_no_rank_pairing"
            for row in report["rq2_full_minus_ablation_rows"]
        )
    )
    assert verification["status"] == "TARGET_RQ_TABLES_VERIFIED"
    tampered = {
        **report,
        "rq2_full_minus_ablation_rows": [
            {**report["rq2_full_minus_ablation_rows"][0], "top_k": 99},
            *report["rq2_full_minus_ablation_rows"][1:],
        ],
    }
    tampered["target_rq_tables_id"] = content_hash(tampered)
    with pytest.raises(ValueError, match="failed independent replay"):
        verify_target_rq_tables(result, yields, tampered)

    # The independent verifier rejects an altered numerical result.
    estimate = result.families[0].estimates[0]
    tampered_estimate = replace(estimate, point=estimate.point + 0.01)
    tampered_family = replace(
        result.families[0],
        estimates=(tampered_estimate,),
    )
    tampered = replace(
        result,
        families=(tampered_family,),
    )
    tampered_yields = build_target_selector_yields(tampered)

    with pytest.raises(ValueError, match="point estimate"):
        verify_target_shared_evidence(tampered, tampered_yields)

    # New outcomes under the same assignments must produce a new estimate.
    zero_outcomes = tuple(Outcome(item.assignment_id, 1, 1, 0, 0, 0, 0, 0, None)
                          for item in evidence.assignments)
    zero = estimate_target_itt(freeze_assigned_arm_evidence(
        evidence.dispatch, evidence.assignments, zero_outcomes), plan)
    for family in zero.families:
        for effect in family.estimates:
            assert effect.point == effect.standard_error == 0
            assert all(arm.secure_yield == 0 for arm in effect.arm_summaries)
    verify_target_shared_evidence(zero, build_target_selector_yields(zero))


def test_context_activation_fail_closed_without_implementations() -> None:
    evidence, plan = _target_v3_fixture()
    with pytest.raises(ValueError, match="context analysis is blocked"):
        ContextAnalysisPlan("FROZEN", (), content_hash("rule"), content_hash("family"))
    context = copy.deepcopy(plan.context_analysis)
    object.__setattr__(context, "status", "FROZEN")
    with pytest.raises(ValueError, match="context analysis is blocked"):
        estimate_target_itt(evidence, replace(plan, context_analysis=context))


def test_target_v3_missing_assigned_outcome_invalidates_only_its_frozen_family() -> None:
    evidence, plan = _target_v3_fixture()
    missing = next(item for item in evidence.assignments if item.track is PolicyTrack.ATOMIC)
    outcomes = tuple(
        item for item in evidence.outcomes if item.assignment_id != missing.assignment_id
    )
    incomplete = freeze_assigned_arm_evidence(
        evidence.dispatch,
        evidence.assignments,
        outcomes,
        (InfrastructureFailure(missing.assignment_id, "generator", "synthetic failure"),),
    )

    result = estimate_target_itt(incomplete, plan, evidence_level=EvidenceLevel.TESTED)

    assert result.families[0].status is TargetFamilyStatus.INVALID_PROVENANCE
    assert result.families[0].estimates[0].status is ConfirmatoryEffectStatus.NON_EVALUABLE
    assert len(incomplete.outcomes) + len(incomplete.infrastructure_failures) == len(
        incomplete.assignments
    )


def test_target_v3_protocolization_failure_keeps_slots_but_creates_no_test() -> None:
    evidence, plan = _target_v3_fixture()
    candidate = evidence.dispatch.ledger.selected_candidates[0]
    dispatch = freeze_confirmation_dispatch(
        evidence.dispatch.ledger,
        {},
        failures={
            candidate.candidate_record_id: (BridgeStatus.PROTOCOLIZATION_FAILED, "synthetic failure")
        },
    )
    empty = freeze_assigned_arm_evidence(dispatch, (), ())
    result = estimate_target_itt(empty, plan, evidence_level=EvidenceLevel.TESTED)
    yields = build_target_selector_yields(result)
    verification = verify_target_shared_evidence(result, yields)
    assert result.families[0].status is TargetFamilyStatus.NO_ELIGIBLE_COORDINATES
    assert not result.families[0].estimates
    assert len(yields.slots) == 2
    assert all(item.meaningful_yield == 0 and item.effect_status is None for item in yields.slots)
    assert verification["unique_effects"] == 0


def test_target_v3_five_status_boundaries_are_direction_free() -> None:
    margin = 0.1

    assert classify_confirmatory_interval(0.100001, 0.3, margin, evaluable=True) is (
        ConfirmatoryEffectStatus.POSITIVE_MEANINGFUL
    )
    assert classify_confirmatory_interval(-0.3, -0.100001, margin, evaluable=True) is (
        ConfirmatoryEffectStatus.NEGATIVE_MEANINGFUL
    )
    assert classify_confirmatory_interval(-0.1, 0.1, margin, evaluable=True) is (
        ConfirmatoryEffectStatus.PRACTICALLY_NULL
    )
    assert classify_confirmatory_interval(0.1, 0.1, margin, evaluable=True) is (
        ConfirmatoryEffectStatus.PRACTICALLY_NULL
    )
    assert classify_confirmatory_interval(-0.2, 0.2, margin, evaluable=True) is (
        ConfirmatoryEffectStatus.INCONCLUSIVE
    )
    assert classify_confirmatory_interval(None, None, margin, evaluable=False) is (
        ConfirmatoryEffectStatus.NON_EVALUABLE
    )


def test_policy_limits_stay_local_and_unknown_is_a_warning():
    evidence, plan = _target_v3_fixture(("healthy", "constant", "sparse", "missing"))
    plan = replace(plan, maximum_unknown_fraction_among_valid=0.0)
    original = {o.assignment_id: o for o in evidence.outcomes}
    assignments, outcomes, failures = [], [], []
    for a in evidence.assignments:
        if a.policy_key == "sparse" and int(a.task_unit_id.rsplit("-", 1)[1]) >= 2:
            continue
        assignments.append(a)
        if a.policy_key == "missing" and a.arm.value == "atomic_target":
            failures.append(InfrastructureFailure(a.assignment_id, "generator", "synthetic failure"))
        elif a.policy_key == "constant":
            outcomes.append(Outcome(a.assignment_id, 1, 1, 0, 0, 0, 0, 0, None))
        elif a.policy_key == "healthy":
            secure = int(a.arm.value == 'atomic_target' and int(a.task_unit_id.rsplit('-',1)[1]) < 6)
            outcomes.append(Outcome(a.assignment_id, 1, secure,
                                    secure, 1, 1, 1 if secure else None, 1, None))
        else:
            outcomes.append(original[a.assignment_id])
    ledger = freeze_assigned_arm_evidence(evidence.dispatch, assignments, outcomes, failures)
    result = estimate_target_itt(ledger, plan)
    family = result.families[0]
    assert family.status is TargetFamilyStatus.PARTIALLY_EVALUABLE
    by_key = {e.policy_key: e for e in family.estimates}
    assert by_key["healthy"].status is not ConfirmatoryEffectStatus.NON_EVALUABLE
    assert "maximum_unknown_fraction_exceeded" in by_key["healthy"].warnings
    assert by_key["healthy"].point == pytest.approx(.5)
    assert by_key["constant"].point == 0 and by_key["constant"].simultaneous_lower is None
    assert by_key["sparse"].point is not None and by_key["sparse"].task_units == 2
    assert by_key["missing"].point is None and by_key["missing"].assignments == 48
    assert all(by_key[k].status is ConfirmatoryEffectStatus.NON_EVALUABLE
               for k in ("constant", "sparse", "missing"))
    # Failed policies still consume alpha; the healthy interval uses alpha/4.
    from prompt_mechanism_study.experiment.inference import _target_effect_work, _higher_quantile
    dispatch = next(d for d in evidence.dispatch.records if d.policy_key == "healthy")
    work = _target_effect_work(dispatch, PolicyTrack.ATOMIC,
        tuple(a for a in assignments if a.policy_key == "healthy"),
        {o.assignment_id: o for o in outcomes}, {f.assignment_id for f in failures}, plan)
    values, _ = _target_family_bootstrap(PolicyTrack.ATOMIC, (work,), plan)
    assert by_key["healthy"].critical_value == _higher_quantile(values, 1 - plan.alpha / 4)
    yields = build_target_selector_yields(result)
    assert all(y.top_k == 4 for y in yields.selectors)
    verify_target_shared_evidence(result, yields)
    report = build_target_rq_tables(result, yields)
    verify_target_rq_tables(result, yields, report)


def test_rare_event_retains_point_without_discarding_degenerate_resamples():
    evidence, plan = _target_v3_fixture()
    outcomes = []
    for a in evidence.assignments:
        secure = int(a.arm.value == 'atomic_target' and int(a.task_unit_id.rsplit('-',1)[1]) == 0)
        outcomes.append(Outcome(a.assignment_id, 1, 1, secure, secure, 1,
                                secure, secure, None))
    result = estimate_target_itt(freeze_assigned_arm_evidence(
        evidence.dispatch, evidence.assignments, outcomes), plan)
    effect = result.families[0].estimates[0]
    assert effect.point == pytest.approx(1/12)
    assert effect.simultaneous_lower is None
    assert 'unbounded_studentized_bootstrap_tail' in effect.reasons
    assert effect.valid_bootstrap_draws == plan.bootstrap_draws
    verify_target_shared_evidence(result, build_target_selector_yields(result))

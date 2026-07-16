from __future__ import annotations

import hashlib
import math
from typing import Iterable

import pytest
from pydantic import ValidationError

from m5_executor_fixtures import request
from secaware.analysis.cluster_bootstrap import (
    ClusterBootstrapResult,
    linear_percentile,
    task_cluster_bootstrap,
)
from secaware.analysis.itt import estimate_itt, risk_difference
from secaware.analysis.multiple_testing import bonferroni_percentile_quantiles
from secaware.config import AnalysisConfig
from secaware.pipeline.artifact import canonical_sha256
from secaware.randomness import DeterministicRNG
from secaware.schema.experiments import (
    ArmRole,
    AssignmentExecutionStatus,
    FeatureFamily,
    FeatureOperation,
)
from secaware.schema.outcomes import (
    AssignmentEvaluability,
    AssignmentOutcomeRecord,
    CWESecurityOutcome,
    ITTEffectRecord,
)


def _sha(*parts: object) -> str:
    return hashlib.sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


def _analysis_config(
    *,
    bootstrap_samples: int = 40,
    min_independent_tasks: int = 2,
    max_failed_bootstrap_fraction: float = 0.10,
) -> AnalysisConfig:
    return AnalysisConfig(
        bootstrap_samples=bootstrap_samples,
        percentile_method="linear-v1",
        max_failed_bootstrap_fraction=max_failed_bootstrap_fraction,
        ci_level=0.95,
        multiplicity_method="bonferroni",
        min_independent_tasks=min_independent_tasks,
        min_eligible_pairs=2,
        min_flip_rate=0.05,
        max_side_effect_rate_confirmed=0.10,
    )


def _safety_protocol(operation: FeatureOperation = FeatureOperation.ADD):
    return request(FeatureFamily.SAFETY_CONTROL, operation).protocol


def _assignment_outcome(
    protocol,
    task_id: str,
    arm_role: ArmRole,
    *,
    secure: bool = False,
    unknown: bool = False,
    terminal: bool = False,
    target_changed: bool | None = True,
    semantic_compliance: bool | None = True,
    instance_nonce: str = "",
    assignment_nonce: str = "",
) -> AssignmentOutcomeRecord:
    instance_key = _sha(protocol.arm_protocol_id, task_id, instance_nonce)
    assignment_key = _sha(protocol.arm_protocol_id, task_id, arm_role.value, assignment_nonce)
    if terminal:
        execution_status = AssignmentExecutionStatus.TERMINAL_NO_CODE
        cwe = CWESecurityOutcome.UNKNOWN
        evaluability = AssignmentEvaluability.NOT_REQUIRED_NO_CODE
        parse_ok = False
        functional_ok = False
        primary = 0
    elif unknown:
        execution_status = AssignmentExecutionStatus.GENERATED
        cwe = CWESecurityOutcome.UNKNOWN
        evaluability = AssignmentEvaluability.UNKNOWN_PARSE_FAILURE
        parse_ok = False
        functional_ok = False
        primary = 0
    else:
        execution_status = AssignmentExecutionStatus.GENERATED
        cwe = CWESecurityOutcome.SECURE if secure else CWESecurityOutcome.INSECURE
        evaluability = AssignmentEvaluability.EVALUABLE
        parse_ok = True
        functional_ok = True
        primary = int(secure)
    return AssignmentOutcomeRecord.from_content(
        assignment_id="assignment_" + assignment_key,
        task_id=task_id,
        hypothesis_id=protocol.hypothesis_id,
        target_spec_id=protocol.target_spec_id,
        target_instance_id="target_instance_" + instance_key,
        arm_protocol_id=protocol.arm_protocol_id,
        protocol_instance_id="protocol_instance_" + instance_key,
        variant_id="variant_" + _sha(assignment_key, "variant"),
        arm_role=arm_role,
        model_id="model-a",
        seed_id=int(assignment_key[:15], 16),
        execution_status=execution_status,
        secure_functional_success=primary,
        cwe_security_outcome=cwe,
        oracle_evaluability=evaluability,
        parse_ok=parse_ok,
        functional_ok=functional_ok,
        target_changed=target_changed,
        semantic_compliance=semantic_compliance,
        source_digests_sha256=_sha(assignment_key, "sources"),
    )


def _complete_rows(
    protocol,
    task_ids: Iterable[str],
    *,
    secure_assignments: set[tuple[str, ArmRole]] | None = None,
    unknown_assignments: set[tuple[str, ArmRole]] | None = None,
    terminal_assignments: set[tuple[str, ArmRole]] | None = None,
) -> tuple[AssignmentOutcomeRecord, ...]:
    secure_assignments = secure_assignments or set()
    unknown_assignments = unknown_assignments or set()
    terminal_assignments = terminal_assignments or set()
    return tuple(
        _assignment_outcome(
            protocol,
            task_id,
            arm_role,
            secure=(task_id, arm_role) in secure_assignments,
            unknown=(task_id, arm_role) in unknown_assignments,
            terminal=(task_id, arm_role) in terminal_assignments,
        )
        for task_id in task_ids
        for arm_role in protocol.arm_roles
    )


def _rows_for_model(
    rows: Iterable[AssignmentOutcomeRecord],
    model_id: str,
) -> tuple[AssignmentOutcomeRecord, ...]:
    cloned: list[AssignmentOutcomeRecord] = []
    for row in rows:
        content = row.model_dump(mode="python", exclude={"outcome_id"})
        content.update(
            assignment_id="assignment_" + _sha(row.assignment_id, model_id),
            variant_id="variant_" + _sha(row.variant_id, model_id),
            model_id=model_id,
            source_digests_sha256=_sha(row.source_digests_sha256, model_id),
        )
        cloned.append(AssignmentOutcomeRecord.from_content(**content))
    return tuple(cloned)


def _replace_instance_ids(
    row: AssignmentOutcomeRecord,
    *,
    target_instance_id: str | None = None,
    protocol_instance_id: str | None = None,
) -> AssignmentOutcomeRecord:
    content = row.model_dump(mode="python", exclude={"outcome_id"})
    if target_instance_id is not None:
        content["target_instance_id"] = target_instance_id
    if protocol_instance_id is not None:
        content["protocol_instance_id"] = protocol_instance_id
    return AssignmentOutcomeRecord.from_content(**content)


def _effect(effects: tuple[ITTEffectRecord, ...], contrast_id: str) -> ITTEffectRecord:
    return next(item for item in effects if item.contrast_id == contrast_id)


def test_safety_add_primary_itt_matches_hand_calculation_and_exact_denominator() -> None:
    protocol = _safety_protocol()
    tasks = tuple(f"task-{index}" for index in range(4))
    rows = _complete_rows(
        protocol,
        tasks,
        secure_assignments={
            (tasks[0], ArmRole.TARGET_PATCH),
            (tasks[1], ArmRole.TARGET_PATCH),
            (tasks[2], ArmRole.TARGET_PATCH),
            (tasks[0], ArmRole.NOOP_REWRITE),
        },
    )

    effects = estimate_itt(rows, _analysis_config(), protocols=(protocol,))
    primary = _effect(
        effects,
        "safety_add.target_minus_noop.y_secure_functional",
    )

    assert primary.treatment_n == 4
    assert primary.control_n == 4
    assert primary.independent_task_n == 4
    assert primary.risk_difference == pytest.approx((3 / 4) - (1 / 4))


def test_risk_difference_uses_assigned_arms_and_empty_arm_fails_closed() -> None:
    protocol = _safety_protocol()
    rows = (
        _assignment_outcome(protocol, "task-a", ArmRole.TARGET_PATCH, secure=True),
        _assignment_outcome(protocol, "task-a", ArmRole.NOOP_REWRITE, secure=False),
        _assignment_outcome(protocol, "task-b", ArmRole.TARGET_PATCH, secure=False),
        _assignment_outcome(protocol, "task-b", ArmRole.NOOP_REWRITE, secure=False),
    )

    assert risk_difference(
        rows,
        ArmRole.TARGET_PATCH,
        ArmRole.NOOP_REWRITE,
        lambda row: row.secure_functional_success,
    ) == (0.5, 2, 2)
    with pytest.raises(Exception, match="contrast"):
        risk_difference(
            rows,
            ArmRole.TARGET_PATCH,
            ArmRole.GENERIC_SECURITY_REMINDER,
            lambda row: row.secure_functional_success,
        )


def test_duplicate_assignment_rows_and_multiple_instance_pairs_are_rejected() -> None:
    protocol = _safety_protocol()
    rows = _complete_rows(protocol, ("task-a", "task-b"))
    with pytest.raises(Exception, match="ITT"):
        estimate_itt((*rows, rows[0]), _analysis_config(), protocols=(protocol,))

    changed = _assignment_outcome(
        protocol,
        rows[0].task_id,
        rows[0].arm_role,
        instance_nonce="second-instance",
        assignment_nonce="second-assignment",
    )
    with pytest.raises(Exception, match="ITT"):
        estimate_itt((changed, *rows[1:]), _analysis_config(), protocols=(protocol,))


@pytest.mark.parametrize("invalid_block", ("split-arms", "missing-arm", "unequal-repeats"))
def test_each_semantic_model_task_is_a_complete_equal_count_protocol_block(
    invalid_block: str,
) -> None:
    protocol = _safety_protocol()
    rows = _complete_rows(protocol, ("task-a", "task-b"))
    if invalid_block == "split-arms":
        halfway = len(protocol.arm_roles) // 2
        selected = {("task-a", role) for role in protocol.arm_roles[:halfway]} | {
            ("task-b", role) for role in protocol.arm_roles[halfway:]
        }
        forged = tuple(row for row in rows if (row.task_id, row.arm_role) in selected)
    elif invalid_block == "missing-arm":
        missing = protocol.arm_roles[-1]
        forged = tuple(row for row in rows if row.arm_role is not missing)
    else:
        repeated = _assignment_outcome(
            protocol,
            "task-a",
            protocol.arm_roles[0],
            assignment_nonce="unequal-repeat",
        )
        forged = (*rows, repeated)

    with pytest.raises(Exception, match="complete block"):
        estimate_itt(forged, _analysis_config(), protocols=(protocol,))


def test_equal_repeats_preserve_a_complete_randomized_block() -> None:
    protocol = _safety_protocol()
    rows = _complete_rows(protocol, ("task-a", "task-b"))
    repeated = tuple(
        _assignment_outcome(
            protocol,
            task_id,
            arm_role,
            assignment_nonce="equal-repeat",
        )
        for task_id in ("task-a", "task-b")
        for arm_role in protocol.arm_roles
    )

    effects = estimate_itt((*rows, *repeated), _analysis_config(), protocols=(protocol,))

    assert all(effect.treatment_n == 4 for effect in effects)
    assert all(effect.control_n == 4 for effect in effects)


@pytest.mark.parametrize("reuse", ("pair", "target", "protocol"))
def test_task_bound_instance_ids_cannot_be_reused_by_another_task(reuse: str) -> None:
    protocol = _safety_protocol()
    rows = _complete_rows(protocol, ("task-a", "task-b"))
    owner = next(row for row in rows if row.task_id == "task-a")
    forged: list[AssignmentOutcomeRecord] = []
    for row in rows:
        if row.task_id != "task-b":
            forged.append(row)
            continue
        content = row.model_dump(mode="python", exclude={"outcome_id"})
        if reuse in {"pair", "target"}:
            content["target_instance_id"] = owner.target_instance_id
        if reuse in {"pair", "protocol"}:
            content["protocol_instance_id"] = owner.protocol_instance_id
        forged.append(AssignmentOutcomeRecord.from_content(**content))

    with pytest.raises(Exception, match="ITT"):
        estimate_itt(tuple(forged), _analysis_config(), protocols=(protocol,))


@pytest.mark.parametrize("reuse", ("protocol", "pair"))
def test_protocol_instance_or_pair_cannot_be_reused_across_protocols(reuse: str) -> None:
    contractless = request(
        FeatureFamily.TASK_FUNCTION,
        FeatureOperation.ADD,
        with_functional_contract=False,
    ).protocol
    contracted = request(
        FeatureFamily.TASK_FUNCTION,
        FeatureOperation.ADD,
        with_functional_contract=True,
    ).protocol
    assert contractless.target_spec_id == contracted.target_spec_id
    left = _complete_rows(contractless, ("task-a", "task-b"))
    right = _complete_rows(contracted, ("task-a", "task-b"))
    owners = {row.task_id: row for row in left}
    forged = tuple(
        _replace_instance_ids(
            row,
            target_instance_id=(
                owners[row.task_id].target_instance_id if reuse == "pair" else None
            ),
            protocol_instance_id=owners[row.task_id].protocol_instance_id,
        )
        for row in right
    )

    with pytest.raises(Exception, match="instance ownership"):
        estimate_itt(
            (*left, *forged),
            _analysis_config(),
            protocols=(contractless, contracted),
        )


def test_target_instance_can_span_protocols_at_the_same_task_target_coordinate() -> None:
    contractless = request(
        FeatureFamily.TASK_FUNCTION,
        FeatureOperation.ADD,
        with_functional_contract=False,
    ).protocol
    contracted = request(
        FeatureFamily.TASK_FUNCTION,
        FeatureOperation.ADD,
        with_functional_contract=True,
    ).protocol
    left = _complete_rows(contractless, ("task-a", "task-b"))
    owners = {row.task_id: row for row in left}
    right = tuple(
        _replace_instance_ids(
            row,
            target_instance_id=owners[row.task_id].target_instance_id,
        )
        for row in _complete_rows(contracted, ("task-a", "task-b"))
    )

    effects = estimate_itt(
        (*left, *right),
        _analysis_config(),
        protocols=(contractless, contracted),
    )

    assert {effect.arm_protocol_id for effect in effects} == {
        contractless.arm_protocol_id,
        contracted.arm_protocol_id,
    }


def test_task_protocol_instances_are_intentionally_model_independent() -> None:
    protocol = _safety_protocol()
    model_a = _complete_rows(protocol, ("task-a", "task-b"))
    model_b = _rows_for_model(model_a, "model-b")

    effects = estimate_itt((*model_a, *model_b), _analysis_config(), protocols=(protocol,))

    assert {effect.model_id for effect in effects} == {"model-a", "model-b"}
    for task_id in ("task-a", "task-b"):
        task_rows = tuple(row for row in (*model_a, *model_b) if row.task_id == task_id)
        assert len({row.target_instance_id for row in task_rows}) == 1
        assert len({row.protocol_instance_id for row in task_rows}) == 1


def test_semantic_protocol_pools_many_distinct_task_instances() -> None:
    protocol = _safety_protocol()
    tasks = tuple(f"task-{index:02d}" for index in range(20))
    rows = _complete_rows(protocol, tasks)

    primary = _effect(
        estimate_itt(
            rows,
            _analysis_config(min_independent_tasks=20),
            protocols=(protocol,),
        ),
        "safety_add.target_minus_noop.y_secure_functional",
    )

    assert primary.independent_task_n == 20
    assert primary.target_spec_id == protocol.target_spec_id
    assert primary.arm_protocol_id == protocol.arm_protocol_id
    assert len({row.target_instance_id for row in rows}) == 20
    assert len({row.protocol_instance_id for row in rows}) == 20
    semantic_group = [
        protocol.hypothesis_id,
        protocol.target_spec_id,
        protocol.arm_protocol_id,
        "model-a",
    ]
    assert primary.assignment_universe_sha256 == canonical_sha256(
        {
            "schema_version": "1.0",
            "semantic_group": semantic_group,
            "assignments": [
                {
                    "assignment_id": row.assignment_id,
                    "execution_status": row.execution_status.value,
                    "secure_functional_success": row.secure_functional_success,
                    "cwe_security_outcome": row.cwe_security_outcome.value,
                    "oracle_evaluability": row.oracle_evaluability.value,
                    "parse_ok": row.parse_ok,
                    "functional_ok": row.functional_ok,
                }
                for row in sorted(rows, key=lambda item: item.assignment_id)
            ],
        }
    )
    assert primary.target_instance_universe_sha256 == canonical_sha256(
        {
            "schema_version": "1.0",
            "semantic_group": semantic_group,
            "instances": [
                {
                    "task_id": task_id,
                    "target_instance_id": target_instance_id,
                    "protocol_instance_id": protocol_instance_id,
                }
                for task_id, target_instance_id, protocol_instance_id in sorted(
                    {
                        (row.task_id, row.target_instance_id, row.protocol_instance_id)
                        for row in rows
                    }
                )
            ],
        }
    )


def test_minimum_independent_task_requirement_is_hard() -> None:
    protocol = _safety_protocol()
    rows = _complete_rows(protocol, ("task-a", "task-b"))

    with pytest.raises(Exception, match="independent task"):
        estimate_itt(
            rows,
            _analysis_config(min_independent_tasks=3),
            protocols=(protocol,),
        )


def test_cluster_bootstrap_draws_sorted_task_ids_and_whole_clusters() -> None:
    protocol = _safety_protocol()
    rows = (
        _assignment_outcome(protocol, "task-b", ArmRole.TARGET_PATCH, assignment_nonce="1"),
        _assignment_outcome(protocol, "task-a", ArmRole.TARGET_PATCH, assignment_nonce="1"),
        _assignment_outcome(protocol, "task-a", ArmRole.NOOP_REWRITE, assignment_nonce="2"),
        _assignment_outcome(
            protocol,
            "task-a",
            ArmRole.LENGTH_MATCHED_PLACEBO,
            assignment_nonce="3",
        ),
    )
    observed_rows: list[tuple[str, ...]] = []

    result = task_cluster_bootstrap(
        rows,
        lambda sample: observed_rows.append(tuple(row.task_id for row in sample)) or 0.0,
        samples=12,
        seed_material=b"cluster-order-golden",
        max_failed_fraction=0.0,
    )

    rng = DeterministicRNG(b"cluster-order-golden")
    task_ids = ("task-a", "task-b")
    expected_draws = tuple(tuple(rng.choice(task_ids) for _ in task_ids) for _ in range(12))
    assert result.task_draws == expected_draws
    assert len(observed_rows) == 12
    assert tuple(len(item) for item in observed_rows) == tuple(
        sum(3 if task_id == "task-a" else 1 for task_id in draw) for draw in expected_draws
    )
    assert set(map(len, observed_rows)) != {len(rows)}  # not row-wise resampling
    repeated = task_cluster_bootstrap(
        tuple(reversed(rows)),
        lambda _sample: 0.0,
        samples=12,
        seed_material=b"cluster-order-golden",
        max_failed_fraction=0.0,
    )
    assert repeated == result


def test_linear_v1_percentile_uses_exact_linear_interpolation() -> None:
    values = (0.0, 10.0, 20.0, 30.0)

    assert linear_percentile(values, 0.0, method="linear-v1") == 0.0
    assert linear_percentile(values, 0.25, method="linear-v1") == pytest.approx(7.5)
    assert linear_percentile(values, 0.50, method="linear-v1") == pytest.approx(15.0)
    assert linear_percentile(values, 1.0, method="linear-v1") == 30.0


def test_failed_bootstrap_replicates_are_counted_and_bounded() -> None:
    protocol = _safety_protocol()
    rows = _complete_rows(protocol, ("task-a", "task-b"))
    calls = 0

    def one_failure(_sample: tuple[AssignmentOutcomeRecord, ...]) -> float:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ValueError("replicate failed")
        return float(calls)

    accepted = task_cluster_bootstrap(
        rows,
        one_failure,
        samples=4,
        seed_material=b"one-failure",
        max_failed_fraction=0.25,
    )
    assert accepted.failed_replicates == 1
    assert len(accepted.estimates) == 3

    with pytest.raises(Exception, match="bootstrap"):
        task_cluster_bootstrap(
            rows,
            lambda _sample: (_ for _ in ()).throw(ValueError("always")),
            samples=4,
            seed_material=b"all-fail",
            max_failed_fraction=0.25,
        )


def test_low_level_bootstrap_rejects_draw_entry_budget_before_rng(monkeypatch) -> None:
    import secaware.analysis.cluster_bootstrap as bootstrap_module

    protocol = _safety_protocol()
    rows = tuple(
        _assignment_outcome(protocol, f"task-{index:03d}", protocol.arm_roles[0])
        for index in range(101)
    )
    rng_constructed = False

    class ForbiddenRNG:
        def __init__(self, _seed: bytes) -> None:
            nonlocal rng_constructed
            rng_constructed = True
            raise AssertionError("resource guard must run before RNG construction")

    monkeypatch.setattr(bootstrap_module, "DeterministicRNG", ForbiddenRNG)

    with pytest.raises(Exception, match="bootstrap"):
        task_cluster_bootstrap(
            rows,
            lambda _sample: 0.0,
            samples=9_901,
            seed_material=b"entry-budget-probe",
            max_failed_fraction=0.0,
        )
    assert not rng_constructed


def test_low_level_bootstrap_rejects_worst_case_json_bytes_before_rng(monkeypatch) -> None:
    import secaware.analysis.cluster_bootstrap as bootstrap_module

    protocol = _safety_protocol()

    def long_task_id(index: int) -> str:
        prefix = f"task-{index}-"
        return prefix + "x" * (256 - len(prefix))

    rows = tuple(
        _assignment_outcome(protocol, long_task_id(index), protocol.arm_roles[0])
        for index in range(7)
    )
    rng_constructed = False

    class ForbiddenRNG:
        def __init__(self, _seed: bytes) -> None:
            nonlocal rng_constructed
            rng_constructed = True
            raise AssertionError("byte budget must run before RNG construction")

    monkeypatch.setattr(bootstrap_module, "DeterministicRNG", ForbiddenRNG)

    with pytest.raises(Exception, match="bootstrap"):
        task_cluster_bootstrap(
            rows,
            lambda _sample: 0.0,
            samples=10_000,
            seed_material=b"byte-budget-probe",
            max_failed_fraction=0.0,
        )
    assert not rng_constructed


def test_low_level_bootstrap_rejects_worst_case_sampled_row_budget_before_rng(
    monkeypatch,
) -> None:
    import secaware.analysis.cluster_bootstrap as bootstrap_module

    protocol = _safety_protocol()
    samples = 10_000
    draw_width = 2
    max_cluster_size = (5_000_000 // (samples * draw_width)) + 1
    rows = (
        *(
            _assignment_outcome(
                protocol,
                "task-large",
                protocol.arm_roles[0],
                assignment_nonce=f"large-{index}",
            )
            for index in range(max_cluster_size)
        ),
        _assignment_outcome(protocol, "task-small", protocol.arm_roles[0]),
    )
    rng_constructed = False

    class ForbiddenRNG:
        def __init__(self, _seed: bytes) -> None:
            nonlocal rng_constructed
            rng_constructed = True
            raise AssertionError("sampled-row guard must run before RNG construction")

    monkeypatch.setattr(bootstrap_module, "DeterministicRNG", ForbiddenRNG)

    with pytest.raises(Exception, match="bootstrap"):
        task_cluster_bootstrap(
            rows,
            lambda _sample: 0.0,
            samples=samples,
            seed_material=b"sampled-row-budget-probe",
            max_failed_fraction=0.0,
        )
    assert not rng_constructed


def test_estimator_rejects_global_task_draw_budget_before_any_bootstrap(monkeypatch) -> None:
    import secaware.analysis.itt as itt_module

    protocol = _safety_protocol()
    base = _complete_rows(protocol, ("task-a", "task-b"))
    samples = 10_000
    group_work = samples * 2 * len(protocol.contrasts)
    model_count = (5_000_000 // group_work) + 1
    rows = tuple(
        cloned
        for index in range(model_count)
        for cloned in _rows_for_model(base, f"model-{index:03d}")
    )
    bootstrap_called = False

    def forbidden_bootstrap(*_args, **_kwargs):
        nonlocal bootstrap_called
        bootstrap_called = True
        raise AssertionError("global budget must run before bootstrap")

    monkeypatch.setattr(itt_module, "task_cluster_bootstrap", forbidden_bootstrap)

    with pytest.raises(Exception, match="work budget"):
        estimate_itt(
            rows,
            _analysis_config(bootstrap_samples=samples),
            protocols=(protocol,),
        )
    assert not bootstrap_called


def test_estimator_preflight_counts_equal_repeat_row_amplification(monkeypatch) -> None:
    import secaware.analysis.itt as itt_module

    protocol = _safety_protocol()
    samples = 10_000
    task_ids = ("task-a", "task-b")
    rows_per_repeat = len(task_ids) * len(protocol.arm_roles)
    repeats = (5_000_000 // (rows_per_repeat * samples * len(protocol.contrasts))) + 1
    rows = tuple(
        _assignment_outcome(
            protocol,
            task_id,
            arm_role,
            assignment_nonce=f"repeat-{repeat}",
        )
        for task_id in task_ids
        for arm_role in protocol.arm_roles
        for repeat in range(repeats)
    )
    assert len(rows) * samples * len(protocol.contrasts) > 5_000_000
    bootstrap_called = False

    def forbidden_bootstrap(*_args, **_kwargs):
        nonlocal bootstrap_called
        bootstrap_called = True
        raise AssertionError("row work budget must run before bootstrap")

    monkeypatch.setattr(itt_module, "task_cluster_bootstrap", forbidden_bootstrap)

    with pytest.raises(Exception, match="work budget"):
        estimate_itt(
            rows,
            _analysis_config(bootstrap_samples=samples),
            protocols=(protocol,),
        )
    assert not bootstrap_called


@pytest.mark.parametrize("malformation", ("failed-replicate", "missing-draw"))
def test_estimator_requires_zero_failed_replicates_and_complete_manifest(
    monkeypatch,
    malformation: str,
) -> None:
    import secaware.analysis.itt as itt_module

    protocol = _safety_protocol()
    rows = _complete_rows(protocol, ("task-a", "task-b"))
    samples = 40

    def malformed_bootstrap(*_args, **_kwargs):
        failed = int(malformation == "failed-replicate")
        draw_count = samples - int(malformation == "missing-draw")
        return ClusterBootstrapResult(
            estimates=(0.0,) * (samples - failed),
            failed_replicates=failed,
            task_draws=(("task-a", "task-b"),) * draw_count,
            manifest_sha256="a" * 64,
        )

    monkeypatch.setattr(itt_module, "task_cluster_bootstrap", malformed_bootstrap)

    with pytest.raises(Exception, match="bootstrap manifest"):
        estimate_itt(rows, _analysis_config(), protocols=(protocol,))


def test_bonferroni_uses_preregistered_family_size_not_valid_effect_count() -> None:
    low, high = bonferroni_percentile_quantiles(
        confidence_level=0.95,
        number_of_pre_registered_contrasts=5,
        multiplicity_method="bonferroni",
    )

    assert low == pytest.approx(0.005)
    assert high == pytest.approx(0.995)


def test_estimator_passes_the_complete_frozen_family_size_to_bonferroni(monkeypatch) -> None:
    import secaware.analysis.itt as itt_module

    protocol = _safety_protocol()
    rows = _complete_rows(protocol, ("task-a", "task-b"))
    observed_family_sizes: list[int] = []
    original = itt_module.bonferroni_percentile_quantiles

    def observed(**kwargs):
        observed_family_sizes.append(kwargs["number_of_pre_registered_contrasts"])
        return original(**kwargs)

    monkeypatch.setattr(itt_module, "bonferroni_percentile_quantiles", observed)

    effects = estimate_itt(rows, _analysis_config(), protocols=(protocol,))

    assert len(effects) == len(protocol.contrasts)
    assert observed_family_sizes == [len(protocol.contrasts)] * len(protocol.contrasts)


@pytest.mark.parametrize(
    "update",
    (
        {"bootstrap_samples": 0},
        {"bootstrap_samples": True},
        {"bootstrap_samples": 10_001},
        {"percentile_method": "nearest"},
        {"max_failed_bootstrap_fraction": -0.01},
        {"max_failed_bootstrap_fraction": 1.0},
        {"max_failed_bootstrap_fraction": float("nan")},
        {"ci_level": 0.0},
        {"ci_level": 1.0},
        {"ci_level": float("inf")},
        {"multiplicity_method": "benjamini-hochberg"},
        {"min_independent_tasks": 1},
        {"min_independent_tasks": True},
    ),
)
def test_analysis_config_predeclares_strict_finite_itt_coordinates(
    update: dict[str, object],
) -> None:
    payload = _analysis_config().model_dump(mode="python")
    payload.update(update)

    with pytest.raises(ValidationError):
        AnalysisConfig.model_validate(payload)


def test_itt_effect_is_strict_frozen_finite_and_content_addressed() -> None:
    protocol = _safety_protocol()
    rows = _complete_rows(protocol, ("task-a", "task-b"))
    record = estimate_itt(rows, _analysis_config(), protocols=(protocol,))[0]

    assert record.schema_version == "1.0"
    assert record.effect_id.startswith("itt_effect_")
    assert tuple(ITTEffectRecord.model_fields) == (
        "schema_version",
        "effect_id",
        "hypothesis_id",
        "target_spec_id",
        "arm_protocol_id",
        "model_id",
        "contrast_id",
        "outcome_id",
        "treatment_n",
        "control_n",
        "independent_task_n",
        "risk_difference",
        "ci_low",
        "ci_high",
        "sensitivity_low",
        "sensitivity_high",
        "status",
        "assignment_universe_sha256",
        "target_instance_universe_sha256",
        "bootstrap_manifest_sha256",
    )
    with pytest.raises(ValidationError):
        record.status = "forged"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        ITTEffectRecord.model_validate(record.model_copy(update={"risk_difference": float("nan")}))
    with pytest.raises(ValidationError):
        ITTEffectRecord.model_validate(record.model_copy(update={"status": "forged"}))


def test_itt_effect_from_content_normalizes_zero_and_direct_negative_zero_is_rejected() -> None:
    protocol = _safety_protocol()
    rows = _complete_rows(protocol, ("task-a", "task-b"))
    zero = estimate_itt(rows, _analysis_config(), protocols=(protocol,))[0]
    numeric_fields = (
        "risk_difference",
        "ci_low",
        "ci_high",
        "sensitivity_low",
        "sensitivity_high",
    )
    plus_payload = zero.model_dump(mode="python", exclude={"schema_version", "effect_id"})
    minus_payload = {**plus_payload, **{field: -0.0 for field in numeric_fields}}

    normalized = ITTEffectRecord.from_content(**minus_payload)
    canonical = ITTEffectRecord.from_content(**plus_payload)

    assert normalized.effect_id == canonical.effect_id
    assert all(math.copysign(1.0, getattr(normalized, field)) == 1.0 for field in numeric_fields)
    direct_payload = {
        "schema_version": "1.0",
        "effect_id": "itt_effect_" + canonical_sha256({"schema_version": "1.0", **minus_payload}),
        **minus_payload,
    }
    with pytest.raises(ValidationError):
        ITTEffectRecord.model_validate(direct_payload)
    with pytest.raises(ValidationError):
        ITTEffectRecord(**direct_payload)

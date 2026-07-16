from __future__ import annotations

import hashlib
from typing import Iterable

import pytest
from pydantic import ValidationError

from m5_executor_fixtures import request
from secaware.analysis.cluster_bootstrap import linear_percentile, task_cluster_bootstrap
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
            "assignment_ids": sorted(row.assignment_id for row in rows),
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
        {"bootstrap_samples": 100_001},
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

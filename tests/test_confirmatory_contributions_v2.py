from __future__ import annotations

import inspect
from collections import defaultdict
from dataclasses import replace
from fractions import Fraction
from functools import lru_cache

import pytest
from tests.test_population_randomization_v2 import (
    MODELS,
    _committed_assignment,
    _execution_freeze,
    _sha,
    _synthetic_population,
)

from secaware.analysis.confirmatory_contributions_v2 import (
    derive_confirmatory_contributions_v2,
    validate_confirmatory_contribution_artifact_v2,
)
from secaware.experiments.execution_v2 import (
    AssignmentExecutionReceiptV2,
    OutcomeAssemblyReceiptV2,
    ProvenanceClosedAssignmentCoverageManifestV2,
    SyntaxValidationReceiptV2,
)
from secaware.experiments.randomization_v2 import (
    AssignmentUnitKeyV2,
    ModelGenerationParametersV2,
    RandomizationManifestV2,
)
from secaware.schema.experiments import ArmRole
from secaware.schema.inference_v2 import (
    SimultaneousCoordinateKindV2,
    SimultaneousTestCoordinateV2,
)
from secaware.schema.policy_v2 import TaskRealizationBundleRecord
from secaware.schema.runtime_v2 import (
    ConfirmationAssignmentRecordV2,
    FunctionalResultRecordV2,
    GeneratedCodeRecordV2,
    GenerationRequestRecordV2,
    OracleResultRecordV2,
)


def _randomization(population) -> RandomizationManifestV2:
    return RandomizationManifestV2.from_population(
        population=population,
        request_randomness_slots=tuple(range(8)),
        model_generation_parameters=tuple(
            ModelGenerationParametersV2(
                model_id=model_id,
                generation_parameters_sha256=_sha(f"generation-parameters:{model_id}"),
            )
            for model_id in MODELS
        ),
        randomization_seed=20260820,
        bounded_concurrency=2,
    )


def _receipt(
    *,
    unit: AssignmentUnitKeyV2,
    assignment: ConfirmationAssignmentRecordV2,
    bundle: TaskRealizationBundleRecord,
    execution_freeze,
    secure: bool,
) -> OutcomeAssemblyReceiptV2:
    variant = next(item for item in bundle.arms if item.arm_role is unit.assigned_arm)
    coordinates = {
        "regime_id": "randomized_confirmation",
        "semantic_task_cluster_id": assignment.semantic_task_cluster_id,
        "task_instance_id": assignment.task_instance_id,
        "model_id": assignment.model_id,
        "request_randomness_slot": assignment.request_randomness_slot,
        "provider_seed": assignment.provider_seed,
        "assignment_id": assignment.assignment_id,
        "hypothesis_id": assignment.hypothesis_id,
        "target_spec_id": assignment.target_spec_id,
        "realization_spec_id": assignment.realization_spec_id,
        "task_realization_bundle_id": assignment.task_realization_bundle_id,
        "variant_id": assignment.variant_id,
        "arm_protocol_id": assignment.arm_protocol_id,
        "block_id": assignment.block_id,
        "assigned_arm": assignment.assigned_arm,
    }
    model_id = unit.block.model_id
    request = GenerationRequestRecordV2.from_content(
        **coordinates,
        prompt_id=variant.variant_prompt_id,
        prompt=variant.prompt_text,
        prompt_sha256=variant.prompt_sha256,
        language="python",
        endpoint_sha256=_sha(f"endpoint:{model_id}"),
        generation_parameters_sha256=unit.generation_parameters_sha256,
        system_template_sha256=_sha(f"system-template:{model_id}"),
        generator_producer_id="generator.synthetic",
        generator_policy_sha256=_sha(f"generator-policy:{model_id}"),
    )
    execution = AssignmentExecutionReceiptV2.from_request(
        execution_policy_freeze=execution_freeze,
        assignment_unit=unit,
        committed_assignment=assignment,
        task_realization_bundle=bundle,
        generation_request=request,
    )
    code_text = "def generated():\n    return 1\n"
    code = GeneratedCodeRecordV2.from_content(
        **coordinates,
        generation_request_id=request.generation_request_id,
        code_status="generated",
        code=code_text,
        code_sha256=_sha(code_text),
        terminal_reason=None,
        provider_response_sha256=_sha(f"response:{unit.assignment_id}"),
        generator_runtime_sha256=_sha("generator-runtime:contribution-test"),
    )
    oracle = OracleResultRecordV2.from_content(
        **coordinates,
        generated_code_id=code.generated_code_id,
        code_sha256=code.code_sha256,
        status="secure" if secure else "insecure",
        oracle_supported=True,
        oracle_evaluable=True,
        evidence_sha256=_sha(f"oracle:{unit.assignment_id}:{secure}"),
        oracle_producer_id="oracle.synthetic",
        oracle_policy_sha256=_sha("oracle-policy:synthetic"),
        oracle_runtime_sha256=_sha("oracle-runtime:contribution-test"),
    )
    functional = FunctionalResultRecordV2.from_content(
        **coordinates,
        generated_code_id=code.generated_code_id,
        code_sha256=code.code_sha256,
        status="pass",
        evidence_sha256=_sha(f"functional:{unit.assignment_id}"),
        evaluator_producer_id="functional.synthetic",
        evaluator_policy_sha256=_sha("functional-policy:synthetic"),
        evaluator_runtime_sha256=_sha("functional-runtime:contribution-test"),
    )
    syntax = SyntaxValidationReceiptV2.from_generated_code(
        generated_code=code,
        language="python",
        status="valid",
        parser_producer_id="parser.synthetic",
        parser_policy_sha256=_sha("parser-policy:synthetic"),
        parser_runtime_sha256=_sha("parser-runtime:contribution-test"),
        evidence_sha256=_sha(f"parser:{unit.assignment_id}"),
    )
    return OutcomeAssemblyReceiptV2.from_runtime(
        assignment_execution_receipt=execution,
        generated_code=code,
        syntax_validation=syntax,
        oracle_result=oracle,
        functional_result=functional,
    )


def _secure_assignments(randomization: RandomizationManifestV2) -> set[str]:
    r0, r1 = randomization.population.hypothesis.realization_spec_ids
    block_contrasts = {
        ("task.1", r0): Fraction(1, 2),
        ("task.2", r0): Fraction(0, 1),
        ("task.3", r0): Fraction(1, 2),
        ("task.1", r1): Fraction(-1, 2),
        ("task.2", r1): Fraction(0, 1),
        ("task.3", r1): Fraction(0, 1),
    }
    units: dict[tuple[str, str, str, ArmRole], list[AssignmentUnitKeyV2]] = defaultdict(list)
    for unit in randomization.assignments:
        units[
            (
                unit.block.model_id,
                unit.block.task_instance_id,
                unit.block.realization_spec_id,
                unit.assigned_arm,
            )
        ].append(unit)
    secure: set[str] = set()
    for model_id in MODELS:
        for (task_id, realization_id), contrast in block_contrasts.items():
            target = sorted(
                units[(model_id, task_id, realization_id, ArmRole.TARGET_PATCH)],
                key=lambda item: item.request_randomness_slot,
            )
            control = sorted(
                units[(model_id, task_id, realization_id, ArmRole.NOOP_REWRITE)],
                key=lambda item: item.request_randomness_slot,
            )
            if contrast > 0:
                count = contrast * len(target)
                assert count.denominator == 1
                secure.update(item.assignment_id for item in target[: count.numerator])
            elif contrast < 0:
                count = -contrast * len(control)
                assert count.denominator == 1
                secure.update(item.assignment_id for item in control[: count.numerator])
    return secure


@lru_cache(maxsize=1)
def _closed_fixture():
    population = _synthetic_population().manifest
    randomization = _randomization(population)
    execution_freeze = _execution_freeze(randomization)
    bundles = {
        bundle.task_realization_bundle_id: bundle
        for gate in population.task_gates
        if gate.task_policy_support is not None
        for bundle in gate.task_policy_support.task_realization_bundles
    }
    secure_ids = _secure_assignments(randomization)
    receipts = tuple(
        _receipt(
            unit=unit,
            assignment=_committed_assignment(unit, randomization),
            bundle=bundles[unit.block.task_realization_bundle_id],
            execution_freeze=execution_freeze,
            secure=unit.assignment_id in secure_ids,
        )
        for unit in randomization.assignments
    )
    coverage = ProvenanceClosedAssignmentCoverageManifestV2.from_receipts(
        execution_policy_freeze=execution_freeze,
        outcome_assembly_receipts=receipts,
    )
    return population, coverage


def _coordinate(population, *, model_id: str = "model.alpha", **updates: object):
    hypothesis = population.hypothesis
    content = {
        "hypothesis_id": hypothesis.hypothesis_id,
        "target_spec_id": hypothesis.target_spec_id,
        "arm_protocol_id": hypothesis.arm_protocol_id,
        "model_id": model_id,
        "outcome_name": hypothesis.outcome_id,
        "treatment_arm": ArmRole.TARGET_PATCH,
        "control_arm": ArmRole.NOOP_REWRITE,
        "coordinate_kind": SimultaneousCoordinateKindV2.POLICY_EFFECT,
        "analysis_component_id": "pooled",
    }
    content.update(updates)
    return SimultaneousTestCoordinateV2.from_content(**content)


def test_hand_calculated_block_task_qh_and_cluster_contributions() -> None:
    population, coverage = _closed_fixture()
    coordinate = _coordinate(population)
    artifact = derive_confirmatory_contributions_v2(population, coverage, coordinate)

    # Two observations per arm form each block mean.  Frozen task weights are
    # (1/3, 2/3) in cluster.1 and 1 in cluster.2; Q_h is (1/2, 1/2).
    per_realization = {
        (item.realization_spec_id, item.semantic_task_cluster_id): item.fraction
        for item in artifact.exact_realization_contributions
    }
    r0, r1 = population.hypothesis.realization_spec_ids
    assert per_realization == {
        (r0, "cluster.1"): Fraction(1, 6),
        (r0, "cluster.2"): Fraction(1, 2),
        (r1, "cluster.1"): Fraction(-1, 6),
        (r1, "cluster.2"): Fraction(0, 1),
    }
    pooled = {
        item.semantic_task_cluster_id: item.fraction
        for item in artifact.exact_coordinate_contributions
    }
    assert pooled == {
        "cluster.1": Fraction(0, 1),
        "cluster.2": Fraction(1, 4),
    }
    assert [item.estimate for item in artifact.coordinate_contributions] == [0.0, 0.25]
    assert all(-1.0 <= item.estimate <= 1.0 for item in artifact.realization_contributions)
    assert artifact.population_freeze_manifest_id == population.population_freeze_manifest_id
    assert (
        artifact.randomization_manifest_id
        == coverage.execution_policy_freeze.randomization.randomization_manifest_id
    )
    assert (
        artifact.execution_policy_freeze_manifest_id
        == coverage.execution_policy_freeze.execution_policy_freeze_manifest_id
    )
    assert (
        artifact.provenance_closed_coverage_manifest_id
        == coverage.provenance_closed_coverage_manifest_id
    )
    assert artifact.test_coordinate_id == coordinate.test_coordinate_id
    assert artifact.contribution_artifact_id.startswith("confirmatory_contributions_v2_")
    assert (
        validate_confirmatory_contribution_artifact_v2(population, coverage, coordinate, artifact)
        == artifact
    )
    assert tuple(inspect.signature(derive_confirmatory_contributions_v2).parameters) == (
        "population",
        "coverage",
        "coordinate",
    )


@pytest.mark.parametrize(
    "updates",
    (
        {"hypothesis_id": "hypothesis_" + "f" * 64},
        {"target_spec_id": "target_" + "f" * 64},
        {"arm_protocol_id": "arm_protocol_" + "f" * 64},
        {"model_id": "model.outside"},
        {"outcome_name": "y_c"},
        {
            "treatment_arm": ArmRole.NOOP_REWRITE,
            "control_arm": ArmRole.TARGET_PATCH,
        },
    ),
)
def test_coordinate_identity_outcome_and_arm_reversal_fail_closed(
    updates: dict[str, object],
) -> None:
    population, coverage = _closed_fixture()
    with pytest.raises(ValueError, match="coordinate"):
        derive_confirmatory_contributions_v2(
            population,
            coverage,
            _coordinate(population, **updates),
        )


def test_base_coverage_deleted_or_swapped_receipts_and_fake_outcome_fail_closed() -> None:
    population, coverage = _closed_fixture()
    coordinate = _coordinate(population)
    with pytest.raises(ValueError, match="provenance-closed"):
        derive_confirmatory_contributions_v2(
            population,
            coverage.base_coverage,  # type: ignore[arg-type]
            coordinate,
        )

    deleted = coverage.model_copy(
        update={"outcome_assembly_receipts": coverage.outcome_assembly_receipts[:-1]}
    )
    with pytest.raises(ValueError, match="coverage"):
        derive_confirmatory_contributions_v2(population, deleted, coordinate)

    first = coverage.outcome_assembly_receipts[0]
    fake_outcome = first.outcome.model_copy(update={"task_instance_id": "task.swapped"})
    fake_receipt = first.model_copy(update={"outcome": fake_outcome})
    swapped = coverage.model_copy(
        update={
            "outcome_assembly_receipts": (
                fake_receipt,
                *coverage.outcome_assembly_receipts[1:],
            )
        }
    )
    with pytest.raises(ValueError, match="coverage"):
        derive_confirmatory_contributions_v2(population, swapped, coordinate)

    standalone_fake = first.outcome.model_copy(
        update={"y_secure_yield": 1 - first.outcome.y_secure_yield}
    )
    fake_base = coverage.base_coverage.model_copy(
        update={"outcomes": (standalone_fake, *coverage.base_coverage.outcomes[1:])}
    )
    with pytest.raises(ValueError, match="provenance-closed"):
        derive_confirmatory_contributions_v2(
            population,
            fake_base,  # type: ignore[arg-type]
            coordinate,
        )


def test_artifact_task_realization_model_and_coordinate_swaps_are_detected() -> None:
    population, coverage = _closed_fixture()
    coordinate = _coordinate(population)
    artifact = derive_confirmatory_contributions_v2(population, coverage, coordinate)

    deleted_cluster = replace(
        artifact,
        coordinate_contributions=artifact.coordinate_contributions[:-1],
    )
    with pytest.raises(ValueError, match="artifact"):
        validate_confirmatory_contribution_artifact_v2(
            population, coverage, coordinate, deleted_cluster
        )

    first_realization = artifact.realization_contributions[0]
    realization_swap = replace(
        artifact,
        realization_contributions=(
            replace(
                first_realization,
                realization_spec_id=population.hypothesis.realization_spec_ids[1],
            ),
            *artifact.realization_contributions[1:],
        ),
    )
    with pytest.raises(ValueError, match="artifact"):
        validate_confirmatory_contribution_artifact_v2(
            population, coverage, coordinate, realization_swap
        )

    other_model_coordinate = _coordinate(population, model_id="model.beta")
    with pytest.raises(ValueError, match="artifact"):
        validate_confirmatory_contribution_artifact_v2(
            population,
            coverage,
            other_model_coordinate,
            artifact,
        )

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from dataclasses import dataclass
from functools import cache

import pytest
from pydantic import ValidationError

from secaware.analysis.confirmatory_v2 import estimate_manifest_bound_cluster_itt_v2
from secaware.experiments.execution_v2 import (
    AssignmentExecutionReceiptV2,
    ExecutionPolicyFreezeManifestV2,
    InfrastructureFailureReceiptV2,
    MeasurementExecutionPolicyV2,
    ModelExecutionPolicyV2,
    OutcomeAssemblyReceiptV2,
    ProvenanceClosedAssignmentCoverageManifestV2,
    RetryAttemptReceiptV2,
    SyntaxValidationReceiptV2,
    TotalAssignmentAccountingManifestV2,
)
from secaware.experiments.randomization_v2 import (
    AssignmentCoverageManifestV2,
    AssignmentUnitKeyV2,
    ModelGenerationParametersV2,
    RandomizationManifestV2,
)
from secaware.outcomes.assembler_v2 import assemble_assignment_outcome_v2
from secaware.phased_exploration.pools import (
    ContractStatus,
    EvidencePool,
    PoolPartitionManifest,
    PoolTaskRecord,
)
from secaware.schema.experiments import ArmRole
from secaware.schema.features import FeatureOperation
from secaware.schema.outcomes_v2 import (
    AssignmentOutcomeRecordV2,
    AssignmentOutcomeStateV2,
    FunctionalStatusV2,
)
from secaware.schema.policy_v2 import (
    ActionableFeatureQueryResultRecord,
    ActionableFeatureSpec,
    CandidateSkeleton,
    ContextQueryResultRecord,
    ContextQuerySpec,
    ExpectedDirection,
    FrozenPolicyHypothesisRecord,
    GlobalArmExecutionSpec,
    PolicySplit,
    PreOutcomeEligibilityRecord,
    QueryState,
    RealizationPolicySpec,
    RealizationSpecRecord,
    SemanticTaskClusterManifest,
    SemanticTaskClusterMembershipRecord,
    TaskArmVariantBinding,
    TaskPolicySupportRecord,
    TaskRealizationBundleRecord,
)
from secaware.schema.population_v2 import (
    ClusterWeightBindingV2,
    PopulationFreezeManifestV2,
    PopulationTaskGateRecordV2,
    RationalWeightV2,
    ResamplingStratumV2,
)
from secaware.schema.runtime_v2 import (
    ConfirmationAssignmentRecordV2,
    FunctionalResultRecordV2,
    GeneratedCodeRecordV2,
    GenerationRequestRecordV2,
    OracleResultRecordV2,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


SHA_A = _sha("a")
SHA_B = _sha("b")
SHA_C = _sha("c")
SHA_D = _sha("d")
MODELS = ("model.alpha", "model.beta")
TASK_COORDINATES = (
    ("task.1", "cluster.1"),
    ("task.2", "cluster.1"),
    ("task.3", "cluster.2"),
    ("task.4", "cluster.2"),
)


def _context_spec() -> ContextQuerySpec:
    return ContextQuerySpec.from_content(
        query_name="flow.untrusted_to_sql",
        applicable_cwes=("CWE-89",),
        applicable_task_archetypes=("database_query",),
        query_expression_sha256=SHA_A,
        context_query_catalog_sha256=SHA_B,
        query_semantics_version="context-query-v1",
        target_feature_independent=True,
    )


def _feature_spec() -> ActionableFeatureSpec:
    return ActionableFeatureSpec.from_content(
        feature_id="safety.sql_parameterization",
        feature_catalog_sha256=SHA_C,
        allowed_operations=(FeatureOperation.ADD,),
        task_preserving_edit_policy_sha256=SHA_D,
    )


def _policy() -> RealizationPolicySpec:
    return RealizationPolicySpec.from_content(
        k_r=2,
        probability_numerators=(1, 1),
        probability_denominator=2,
        distribution_rationale="uniform",
        matching_rules_sha256=SHA_A,
        executor_policy_sha256=SHA_B,
        extractor_policy_sha256=SHA_C,
        validation_policy_sha256=SHA_D,
        full_support_required=True,
        failure_policy="fail_closed_no_deletion_no_renormalization",
    )


def _skeleton(policy: RealizationPolicySpec) -> CandidateSkeleton:
    context = _context_spec()
    feature = _feature_spec()
    return CandidateSkeleton.from_content(
        context_query_id=context.context_query_id,
        actionable_feature_spec_id=feature.actionable_feature_spec_id,
        feature_id=feature.feature_id,
        operation=FeatureOperation.ADD,
        realization_policy_spec_id=policy.realization_policy_spec_id,
        outcome_id="y_secure_yield",
        expected_direction=ExpectedDirection.POSITIVE,
        cwe="CWE-89",
        task_archetype="database_query",
        model_scope=MODELS,
        context_query_catalog_sha256=SHA_B,
        feature_catalog_sha256=SHA_C,
        eligibility_function_sha256=SHA_D,
    )


ADD_ARMS = (
    ArmRole.TARGET_PATCH,
    ArmRole.NOOP_REWRITE,
    ArmRole.LENGTH_MATCHED_PLACEBO,
    ArmRole.GENERIC_SECURITY_REMINDER,
)


def _realizations(
    skeleton: CandidateSkeleton, policy: RealizationPolicySpec
) -> tuple[RealizationSpecRecord, ...]:
    return tuple(
        RealizationSpecRecord.from_policy(
            skeleton=skeleton,
            policy=policy,
            realization_index=index,
            arms=tuple(
                GlobalArmExecutionSpec(
                    arm_role=arm,
                    template_or_execution_policy_sha256=_sha(
                        f"global-template:{index}:{arm.value}"
                    ),
                    validation_requirements_sha256=SHA_D,
                )
                for arm in ADD_ARMS
            ),
        )
        for index in range(policy.k_r)
    )


def _hypothesis(
    skeleton: CandidateSkeleton,
    policy: RealizationPolicySpec,
    realizations: tuple[RealizationSpecRecord, ...],
) -> FrozenPolicyHypothesisRecord:
    return FrozenPolicyHypothesisRecord.from_components(
        skeleton=skeleton,
        policy=policy,
        realizations=realizations,
        target_spec_id="target_" + SHA_A,
        arm_protocol_id="arm_protocol_" + SHA_B,
        bridge_policy_sha256=SHA_C,
    )


def _pool_task(task_id: str, cluster_id: str) -> PoolTaskRecord:
    return PoolTaskRecord.from_content(
        pool=EvidencePool.FORMAL_CONFIRM,
        semantic_task_cluster_id=cluster_id,
        task_instance_id=task_id,
        source_id="synthetic.registry",
        source_record_id=f"source.{task_id}",
        prompt_sha256=_sha(f"prompt:{task_id}"),
        cwe_id="CWE-89",
        archetype_id="database_query",
        template_family_id="sql.lookup",
        functional_contract_status=ContractStatus.DECLARATIVE_ONLY,
        security_contract_status=ContractStatus.DECLARATIVE_ONLY,
        legacy_outcome_exposed=False,
    )


def _membership(task_id: str, cluster_id: str) -> SemanticTaskClusterMembershipRecord:
    return SemanticTaskClusterMembershipRecord.from_content(
        semantic_task_cluster_id=cluster_id,
        task_instance_id=task_id,
        split=PolicySplit.CONFIRM,
        cwe="CWE-89",
        task_archetype="database_query",
        source_task_sha256=_sha(f"source-task:{task_id}"),
        clustering_policy_sha256=SHA_A,
        adjudication_sha256=None,
    )


def _query_evidence(state: QueryState) -> dict[str, object]:
    if state is QueryState.PRESENT:
        return {
            "applicable": True,
            "required_roles_resolved": True,
            "bounded_matching_complete": True,
            "match_evidence_ids": ("evidence.present",),
        }
    if state is QueryState.ABSENT:
        return {
            "applicable": True,
            "required_roles_resolved": True,
            "bounded_matching_complete": True,
            "match_evidence_ids": (),
        }
    raise AssertionError("synthetic fixture only uses present/absent states")


def _eligibility(task_id: str, *, context_present: bool) -> PreOutcomeEligibilityRecord:
    context = _context_spec()
    feature = _feature_spec()
    coordinates = {
        "regime_id": "natural_prompt_discovery",
        "task_instance_id": task_id,
        "natural_prompt_id": f"natural.{task_id}",
        "prompt_tsg_sha256": _sha(f"prompt-tsg:{task_id}"),
        "context_query_catalog_sha256": SHA_B,
        "query_semantics_version": "context-query-v1",
    }
    context_state = QueryState.PRESENT if context_present else QueryState.ABSENT
    context_result = ContextQueryResultRecord.from_content(
        **coordinates,
        context_query_id=context.context_query_id,
        state=context_state,
        **_query_evidence(context_state),
        evaluation_evidence_sha256=_sha(f"context-evidence:{task_id}"),
    )
    feature_result = ActionableFeatureQueryResultRecord.from_content(
        **coordinates,
        actionable_feature_spec_id=feature.actionable_feature_spec_id,
        feature_id=feature.feature_id,
        feature_catalog_sha256=feature.feature_catalog_sha256,
        state=QueryState.ABSENT,
        **_query_evidence(QueryState.ABSENT),
        evaluation_evidence_sha256=_sha(f"feature-evidence:{task_id}"),
    )
    return PreOutcomeEligibilityRecord.from_query_results(
        context_result=context_result,
        feature_result=feature_result,
        operation=FeatureOperation.ADD,
        eligibility_function_sha256=SHA_D,
    )


def _bundle(
    *,
    task_id: str,
    cluster_id: str,
    hypothesis: FrozenPolicyHypothesisRecord,
    realization: RealizationSpecRecord,
) -> TaskRealizationBundleRecord:
    arms = tuple(
        TaskArmVariantBinding.from_text(
            arm_role=arm,
            prompt_text=f"Synthetic {task_id}; realization {realization.realization_index}; {arm.value}.",
            validation_evidence_sha256=_sha(
                f"variant-validation:{task_id}:{realization.realization_index}:{arm.value}"
            ),
        )
        for arm in ADD_ARMS
    )
    return TaskRealizationBundleRecord.from_components(
        hypothesis=hypothesis,
        realization=realization,
        semantic_task_cluster_id=cluster_id,
        task_instance_id=task_id,
        source_prompt_id=f"source-prompt.{task_id}",
        source_prompt_sha256=_sha(f"prompt:{task_id}"),
        arms=arms,
    )


def _support(
    *,
    task_id: str,
    cluster_id: str,
    hypothesis: FrozenPolicyHypothesisRecord,
    policy: RealizationPolicySpec,
    realizations: tuple[RealizationSpecRecord, ...],
) -> TaskPolicySupportRecord:
    bundles = tuple(
        _bundle(
            task_id=task_id,
            cluster_id=cluster_id,
            hypothesis=hypothesis,
            realization=realization,
        )
        for realization in realizations
    )
    return TaskPolicySupportRecord.from_components(
        hypothesis=hypothesis,
        policy=policy,
        realizations=realizations,
        bundles=bundles,
    )


@dataclass(frozen=True)
class SyntheticPopulation:
    manifest: PopulationFreezeManifestV2
    pool_tasks: dict[str, PoolTaskRecord]
    memberships: dict[str, SemanticTaskClusterMembershipRecord]
    eligibilities: dict[str, PreOutcomeEligibilityRecord]
    supports: dict[str, TaskPolicySupportRecord]


def _synthetic_population() -> SyntheticPopulation:
    policy = _policy()
    skeleton = _skeleton(policy)
    realizations = _realizations(skeleton, policy)
    hypothesis = _hypothesis(skeleton, policy, realizations)
    pool_tasks = {
        task_id: _pool_task(task_id, cluster_id) for task_id, cluster_id in TASK_COORDINATES
    }
    memberships = {
        task_id: _membership(task_id, cluster_id) for task_id, cluster_id in TASK_COORDINATES
    }
    partition = PoolPartitionManifest.from_content(
        partition_version="synthetic-v2",
        semantic_cluster_policy_sha256=SHA_A,
        source_inventory_sha256=SHA_B,
        tasks=tuple(pool_tasks.values()),
    )
    cluster_manifest = SemanticTaskClusterManifest.from_content(
        memberships=tuple(
            sorted(
                memberships.values(),
                key=lambda item: (item.semantic_task_cluster_id, item.task_instance_id),
            )
        ),
        clustering_algorithm_sha256=SHA_A,
        normalization_policy_sha256=SHA_B,
        construction_digest_sha256=SHA_C,
        frozen_before_discovery=True,
    )
    eligibilities = {
        task_id: _eligibility(task_id, context_present=task_id != "task.4")
        for task_id, _ in TASK_COORDINATES
    }
    supports = {
        task_id: _support(
            task_id=task_id,
            cluster_id=cluster_id,
            hypothesis=hypothesis,
            policy=policy,
            realizations=realizations,
        )
        for task_id, cluster_id in TASK_COORDINATES
        if task_id != "task.4"
    }
    weights = {
        "task.1": RationalWeightV2(numerator=1, denominator=3),
        "task.2": RationalWeightV2(numerator=2, denominator=3),
        "task.3": RationalWeightV2(numerator=1, denominator=1),
        "task.4": None,
    }
    gates = tuple(
        PopulationTaskGateRecordV2.from_components(
            pool_task=pool_tasks[task_id],
            cluster_membership=memberships[task_id],
            hypothesis=hypothesis,
            eligibility=eligibilities[task_id],
            task_policy_support=supports.get(task_id),
            within_cluster_task_weight=weights[task_id],
        )
        for task_id, _ in TASK_COORDINATES
    )
    stratum = ResamplingStratumV2(
        stratum_id="stratum:CWE-89:database_query",
        cwe="CWE-89",
        task_archetype="database_query",
        cluster_weights=(
            ClusterWeightBindingV2(
                semantic_task_cluster_id="cluster.1",
                weight=RationalWeightV2(numerator=1, denominator=2),
            ),
            ClusterWeightBindingV2(
                semantic_task_cluster_id="cluster.2",
                weight=RationalWeightV2(numerator=1, denominator=2),
            ),
        ),
    )
    manifest = PopulationFreezeManifestV2.from_components(
        pool_partition=partition,
        semantic_cluster_manifest=cluster_manifest,
        hypothesis=hypothesis,
        confirmation_pool=EvidencePool.FORMAL_CONFIRM,
        task_gates=gates,
        strata=(stratum,),
        minimum_gate_pass_tasks=3,
        minimum_gate_pass_clusters=2,
        population_construction_sha256=SHA_A,
        weighting_policy_sha256=SHA_B,
        stratification_policy_sha256=SHA_C,
    )
    return SyntheticPopulation(
        manifest=manifest,
        pool_tasks=pool_tasks,
        memberships=memberships,
        eligibilities=eligibilities,
        supports=supports,
    )


def _randomization(population: PopulationFreezeManifestV2) -> RandomizationManifestV2:
    return RandomizationManifestV2.from_population(
        population=population,
        request_randomness_slots=(0, 1, 2, 3),
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


def _randomization_with_provider_seeds(
    population: PopulationFreezeManifestV2,
) -> RandomizationManifestV2:
    baseline = _randomization(population)
    provider_seeds = {
        (block.block_id, slot): index
        for index, (block, slot) in enumerate(
            (
                (block, slot)
                for block in baseline.blocks
                for slot in baseline.request_randomness_slots
            ),
            start=1000,
        )
    }
    return RandomizationManifestV2.from_population(
        population=population,
        request_randomness_slots=baseline.request_randomness_slots,
        model_generation_parameters=baseline.model_generation_parameters,
        randomization_seed=baseline.randomization_seed,
        bounded_concurrency=baseline.bounded_concurrency,
        provider_seed_by_block_slot=provider_seeds,
    )


def _execution_freeze(
    randomization: RandomizationManifestV2,
) -> ExecutionPolicyFreezeManifestV2:
    return ExecutionPolicyFreezeManifestV2.from_randomization(
        randomization=randomization,
        model_policies=tuple(
            ModelExecutionPolicyV2(
                model_id=model_id,
                language="python",
                endpoint_sha256=_sha(f"endpoint:{model_id}"),
                generation_parameters_sha256=_sha(f"generation-parameters:{model_id}"),
                system_template_sha256=_sha(f"system-template:{model_id}"),
                generator_producer_id="generator.synthetic",
                generator_policy_sha256=_sha(f"generator-policy:{model_id}"),
            )
            for model_id in MODELS
        ),
        measurement_policy=MeasurementExecutionPolicyV2(
            parser_producer_id="parser.synthetic",
            parser_policy_sha256=_sha("parser-policy:synthetic"),
            oracle_producer_id="oracle.synthetic",
            oracle_policy_sha256=_sha("oracle-policy:synthetic"),
            functional_evaluator_producer_id="functional.synthetic",
            functional_evaluator_policy_sha256=_sha("functional-policy:synthetic"),
        ),
        execution_environment_sha256=_sha("execution-environment:synthetic"),
    )


def _committed_assignment(
    unit: AssignmentUnitKeyV2, randomization: RandomizationManifestV2
) -> ConfirmationAssignmentRecordV2:
    block = unit.block
    return ConfirmationAssignmentRecordV2.from_content(
        regime_id="randomized_confirmation",
        semantic_task_cluster_id=block.semantic_task_cluster_id,
        task_instance_id=block.task_instance_id,
        model_id=block.model_id,
        request_randomness_slot=unit.request_randomness_slot,
        provider_seed=unit.provider_seed,
        assignment_id=unit.assignment_id,
        hypothesis_id=block.hypothesis_id,
        target_spec_id=block.target_spec_id,
        realization_spec_id=block.realization_spec_id,
        task_realization_bundle_id=block.task_realization_bundle_id,
        variant_id=unit.variant_id,
        arm_protocol_id=block.arm_protocol_id,
        block_id=block.block_id,
        assigned_arm=unit.assigned_arm,
        randomization_manifest_sha256=randomization.semantic_sha256,
    )


def _outcome(unit: AssignmentUnitKeyV2) -> AssignmentOutcomeRecordV2:
    block = unit.block
    return AssignmentOutcomeRecordV2.from_content(
        assignment_id=unit.assignment_id,
        block_id=block.block_id,
        semantic_task_cluster_id=block.semantic_task_cluster_id,
        task_instance_id=block.task_instance_id,
        hypothesis_id=block.hypothesis_id,
        target_spec_id=block.target_spec_id,
        realization_spec_id=block.realization_spec_id,
        task_realization_bundle_id=block.task_realization_bundle_id,
        variant_id=unit.variant_id,
        model_id=block.model_id,
        arm_protocol_id=block.arm_protocol_id,
        arm_role=unit.assigned_arm,
        request_randomness_slot=unit.request_randomness_slot,
        provider_seed=unit.provider_seed,
        state=AssignmentOutcomeStateV2.VALID_ORACLE_SECURE,
        functional_status=FunctionalStatusV2.PASS,
        y_c=1,
        y_e=1,
        y_secure_yield=1,
        y_joint=1,
        source_digests_sha256=_sha(f"outcome-sources:{unit.assignment_id}"),
    )


def _authenticated_outcome_receipt(
    *,
    unit: AssignmentUnitKeyV2,
    assignment: ConfirmationAssignmentRecordV2,
    bundle: TaskRealizationBundleRecord,
    execution_freeze: ExecutionPolicyFreezeManifestV2,
    generation_parameters_sha256: str | None = None,
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
        generation_parameters_sha256=(
            unit.generation_parameters_sha256
            if generation_parameters_sha256 is None
            else generation_parameters_sha256
        ),
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
        generator_runtime_sha256=_sha("generator-runtime:synthetic"),
    )
    target = unit.assigned_arm is ArmRole.TARGET_PATCH
    oracle = OracleResultRecordV2.from_content(
        **coordinates,
        generated_code_id=code.generated_code_id,
        code_sha256=code.code_sha256,
        status="secure" if target else "insecure",
        oracle_supported=True,
        oracle_evaluable=True,
        evidence_sha256=_sha(f"oracle:{unit.assignment_id}"),
        oracle_producer_id="oracle.synthetic",
        oracle_policy_sha256=_sha("oracle-policy:synthetic"),
        oracle_runtime_sha256=_sha("oracle-runtime:synthetic"),
    )
    functional = FunctionalResultRecordV2.from_content(
        **coordinates,
        generated_code_id=code.generated_code_id,
        code_sha256=code.code_sha256,
        status="pass",
        evidence_sha256=_sha(f"functional:{unit.assignment_id}"),
        evaluator_producer_id="functional.synthetic",
        evaluator_policy_sha256=_sha("functional-policy:synthetic"),
        evaluator_runtime_sha256=_sha("functional-runtime:synthetic"),
    )
    syntax = SyntaxValidationReceiptV2.from_generated_code(
        generated_code=code,
        language="python",
        status="valid",
        parser_producer_id="parser.synthetic",
        parser_policy_sha256=_sha("parser-policy:synthetic"),
        parser_runtime_sha256=_sha("parser-runtime:synthetic"),
        evidence_sha256=_sha(f"parser:{unit.assignment_id}"),
    )
    return OutcomeAssemblyReceiptV2.from_runtime(
        assignment_execution_receipt=execution,
        generated_code=code,
        syntax_validation=syntax,
        oracle_result=oracle,
        functional_result=functional,
    )


@dataclass(frozen=True)
class AuthenticatedSyntheticExperiment:
    population: PopulationFreezeManifestV2
    randomization: RandomizationManifestV2
    execution_freeze: ExecutionPolicyFreezeManifestV2
    receipts: tuple[OutcomeAssemblyReceiptV2, ...]
    closed_coverage: ProvenanceClosedAssignmentCoverageManifestV2


@cache
def _authenticated_experiment() -> AuthenticatedSyntheticExperiment:
    population = _synthetic_population().manifest
    randomization = _randomization(population)
    execution_freeze = _execution_freeze(randomization)
    bundles = {
        bundle.task_realization_bundle_id: bundle
        for gate in population.task_gates
        if gate.task_policy_support is not None
        for bundle in gate.task_policy_support.task_realization_bundles
    }
    receipts = tuple(
        _authenticated_outcome_receipt(
            unit=unit,
            assignment=_committed_assignment(unit, randomization),
            bundle=bundles[unit.block.task_realization_bundle_id],
            execution_freeze=execution_freeze,
        )
        for unit in randomization.assignments
    )
    closed = ProvenanceClosedAssignmentCoverageManifestV2.from_receipts(
        execution_policy_freeze=execution_freeze,
        outcome_assembly_receipts=receipts,
    )
    return AuthenticatedSyntheticExperiment(
        population=population,
        randomization=randomization,
        execution_freeze=execution_freeze,
        receipts=receipts,
        closed_coverage=closed,
    )


def _without_content_id(model: object, id_field: str) -> dict[str, object]:
    payload = model.model_dump(mode="python", exclude={id_field})  # type: ignore[attr-defined]
    payload.pop("schema_version")
    return payload


@pytest.mark.reviewer
def test_population_freezes_hand_checkable_common_support_and_weights() -> None:
    population = _synthetic_population().manifest

    assert (
        PopulationFreezeManifestV2.model_validate_json(population.model_dump_json()) == population
    )
    assert population.gate_entry_task_count == 4
    assert population.gate_pass_task_count == 3
    assert population.excluded_task_count == 1
    assert population.gate_pass_cluster_count == 2
    assert population.common_model_scope == MODELS
    assert population.gate_pass_task_ids == ("task.1", "task.2", "task.3")
    assert population.excluded_task_ids == ("task.4",)
    exclusion_counts = {item.name: item.count for item in population.exclusion_reason_counts}
    assert exclusion_counts["context_absent"] == 1
    assert exclusion_counts["task_policy_support_missing"] == 0
    assert {item.name for item in population.context_state_counts} == {
        "present",
        "absent",
        "not_applicable",
        "unresolved",
    }

    by_cluster: dict[str, list[PopulationTaskGateRecordV2]] = defaultdict(list)
    for gate in population.task_gates:
        if gate.gate_passed:
            by_cluster[gate.semantic_task_cluster_id].append(gate)
    assert [gate.within_cluster_task_weight.fraction for gate in by_cluster["cluster.1"]] == [
        RationalWeightV2(numerator=1, denominator=3).fraction,
        RationalWeightV2(numerator=2, denominator=3).fraction,
    ]
    assert by_cluster["cluster.2"][0].within_cluster_task_weight.fraction == 1
    assert all(
        binding.weight.fraction == RationalWeightV2(numerator=1, denominator=2).fraction
        for binding in population.strata[0].cluster_weights
    )


@pytest.mark.reviewer
def test_population_rejects_task_or_cluster_deletion_with_synchronized_reweighting() -> None:
    fixture = _synthetic_population()
    population = fixture.manifest
    replacement_task_1 = PopulationTaskGateRecordV2.from_components(
        pool_task=fixture.pool_tasks["task.1"],
        cluster_membership=fixture.memberships["task.1"],
        hypothesis=population.hypothesis,
        eligibility=fixture.eligibilities["task.1"],
        task_policy_support=fixture.supports["task.1"],
        within_cluster_task_weight=RationalWeightV2(numerator=1, denominator=1),
    )
    task_deleted = (
        replacement_task_1,
        *(
            gate
            for gate in population.task_gates
            if gate.task_instance_id not in {"task.1", "task.2"}
        ),
    )
    with pytest.raises(ValidationError, match="population v2 contract failed validation"):
        PopulationFreezeManifestV2.from_components(
            pool_partition=population.pool_partition,
            semantic_cluster_manifest=population.semantic_cluster_manifest,
            hypothesis=population.hypothesis,
            confirmation_pool=population.confirmation_pool,
            task_gates=task_deleted,
            strata=population.strata,
            minimum_gate_pass_tasks=2,
            minimum_gate_pass_clusters=2,
            population_construction_sha256=SHA_A,
            weighting_policy_sha256=SHA_B,
            stratification_policy_sha256=SHA_C,
        )

    first_gate = population.task_gates[0]
    model_subset_content = _without_content_id(first_gate, "population_task_gate_id")
    model_subset_content["common_model_scope"] = ("model.alpha",)
    model_subset_gate = PopulationTaskGateRecordV2.from_content(**model_subset_content)
    with pytest.raises(ValidationError, match="population v2 contract failed validation"):
        PopulationFreezeManifestV2.from_components(
            pool_partition=population.pool_partition,
            semantic_cluster_manifest=population.semantic_cluster_manifest,
            hypothesis=population.hypothesis,
            confirmation_pool=population.confirmation_pool,
            task_gates=(model_subset_gate, *population.task_gates[1:]),
            strata=population.strata,
            minimum_gate_pass_tasks=3,
            minimum_gate_pass_clusters=2,
            population_construction_sha256=SHA_A,
            weighting_policy_sha256=SHA_B,
            stratification_policy_sha256=SHA_C,
        )

    cluster_deleted = tuple(
        gate for gate in population.task_gates if gate.semantic_task_cluster_id == "cluster.1"
    )
    one_cluster_stratum = ResamplingStratumV2(
        stratum_id="stratum:CWE-89:database_query",
        cwe="CWE-89",
        task_archetype="database_query",
        cluster_weights=(
            ClusterWeightBindingV2(
                semantic_task_cluster_id="cluster.1",
                weight=RationalWeightV2(numerator=1, denominator=1),
            ),
        ),
    )
    with pytest.raises(ValidationError, match="population v2 contract failed validation"):
        PopulationFreezeManifestV2.from_components(
            pool_partition=population.pool_partition,
            semantic_cluster_manifest=population.semantic_cluster_manifest,
            hypothesis=population.hypothesis,
            confirmation_pool=population.confirmation_pool,
            task_gates=cluster_deleted,
            strata=(one_cluster_stratum,),
            minimum_gate_pass_tasks=2,
            minimum_gate_pass_clusters=1,
            population_construction_sha256=SHA_A,
            weighting_policy_sha256=SHA_B,
            stratification_policy_sha256=SHA_C,
        )


@pytest.mark.reviewer
def test_randomization_covers_full_grid_and_balances_slots_with_nullable_provider_seed() -> None:
    population = _synthetic_population().manifest
    randomization = _randomization(population)

    assert (
        RandomizationManifestV2.model_validate_json(randomization.model_dump_json())
        == randomization
    )
    # 3 passed tasks x 2 realizations x 2 models; 4 request slots per complete block.
    assert randomization.block_count == 12
    assert randomization.assignment_count == 48
    assert all(item.provider_seed is None for item in randomization.assignments)
    counts: dict[str, Counter[ArmRole]] = defaultdict(Counter)
    slots: dict[str, set[int]] = defaultdict(set)
    for assignment in randomization.assignments:
        counts[assignment.block.block_id][assignment.assigned_arm] += 1
        slots[assignment.block.block_id].add(assignment.request_randomness_slot)
    assert all(counter == Counter({arm: 1 for arm in ADD_ARMS}) for counter in counts.values())
    assert all(value == {0, 1, 2, 3} for value in slots.values())

    first, second = randomization.assignments[:2]
    assert first.assignment_id != second.assignment_id
    changed = _without_content_id(first, "assignment_id")
    changed["provider_seed"] = 17
    changed_unit = AssignmentUnitKeyV2.from_content(**changed)
    assert changed_unit.request_randomness_slot == first.request_randomness_slot
    assert changed_unit.assignment_id != first.assignment_id


def test_randomization_rejects_realization_subset_variant_drift_and_missing_slot() -> None:
    randomization = _randomization(_synthetic_population().manifest)
    removed_realization = randomization.population.hypothesis.realization_spec_ids[1]
    surviving_blocks = tuple(
        item for item in randomization.blocks if item.realization_spec_id != removed_realization
    )
    surviving_block_ids = {item.block_id for item in surviving_blocks}
    surviving_assignments = tuple(
        item for item in randomization.assignments if item.block.block_id in surviving_block_ids
    )
    realization_attack = _without_content_id(randomization, "randomization_manifest_id")
    realization_attack.update(
        {
            "blocks": surviving_blocks,
            "assignments": surviving_assignments,
            "execution_order_assignment_ids": tuple(
                assignment_id
                for assignment_id in randomization.execution_order_assignment_ids
                if assignment_id in {item.assignment_id for item in surviving_assignments}
            ),
            "block_count": len(surviving_blocks),
            "assignment_count": len(surviving_assignments),
        }
    )
    with pytest.raises(ValidationError, match="randomization v2 contract failed validation"):
        RandomizationManifestV2.from_content(**realization_attack)

    original = randomization.assignments[0]
    drifted_content = _without_content_id(original, "assignment_id")
    drifted_content["variant_id"] = "variant_" + SHA_D
    drifted = AssignmentUnitKeyV2.from_content(**drifted_content)
    drift_assignments = (drifted, *randomization.assignments[1:])
    variant_attack = _without_content_id(randomization, "randomization_manifest_id")
    variant_attack["assignments"] = drift_assignments
    variant_attack["execution_order_assignment_ids"] = tuple(
        drifted.assignment_id if value == original.assignment_id else value
        for value in randomization.execution_order_assignment_ids
    )
    with pytest.raises(ValidationError, match="randomization v2 contract failed validation"):
        RandomizationManifestV2.from_content(**variant_attack)

    missing_slot_attack = _without_content_id(randomization, "randomization_manifest_id")
    missing_slot_attack["assignments"] = randomization.assignments[:-1]
    missing_slot_attack["execution_order_assignment_ids"] = tuple(
        value
        for value in randomization.execution_order_assignment_ids
        if value != randomization.assignments[-1].assignment_id
    )
    missing_slot_attack["assignment_count"] = len(randomization.assignments) - 1
    with pytest.raises(ValidationError, match="randomization v2 contract failed validation"):
        RandomizationManifestV2.from_content(**missing_slot_attack)


@pytest.mark.reviewer
def test_assignment_coverage_is_exact_and_rejects_missing_duplicate_or_drift() -> None:
    randomization = _randomization(_synthetic_population().manifest)
    committed = tuple(
        _committed_assignment(unit, randomization) for unit in randomization.assignments
    )
    outcomes = tuple(_outcome(unit) for unit in randomization.assignments)
    coverage = AssignmentCoverageManifestV2.from_components(
        randomization=randomization,
        committed_assignments=committed,
        outcomes=outcomes,
    )
    assert AssignmentCoverageManifestV2.model_validate_json(coverage.model_dump_json()) == coverage
    assert coverage.complete is True
    assert coverage.expected_count == coverage.committed_count == coverage.outcome_count == 48

    with pytest.raises(ValidationError, match="randomization v2 contract failed validation"):
        AssignmentCoverageManifestV2.from_components(
            randomization=randomization,
            committed_assignments=committed,
            outcomes=outcomes[:-1],
        )
    with pytest.raises(ValidationError, match="randomization v2 contract failed validation"):
        AssignmentCoverageManifestV2.from_components(
            randomization=randomization,
            committed_assignments=committed,
            outcomes=(*outcomes, outcomes[0]),
        )

    drifted_content = _without_content_id(committed[0], "assignment_record_id")
    drifted_content["variant_id"] = "variant_" + SHA_D
    drifted = ConfirmationAssignmentRecordV2.from_content(**drifted_content)
    with pytest.raises(ValidationError, match="randomization v2 contract failed validation"):
        AssignmentCoverageManifestV2.from_components(
            randomization=randomization,
            committed_assignments=(drifted, *committed[1:]),
            outcomes=outcomes,
        )


def test_public_itt_entrypoint_derives_support_and_weights_from_frozen_manifests() -> None:
    experiment = _authenticated_experiment()

    result = estimate_manifest_bound_cluster_itt_v2(
        population=experiment.population,
        assignment_coverage=experiment.closed_coverage,
        model_id="model.alpha",
    )

    assert result.cluster_itt.estimate == pytest.approx(1.0)
    assert result.cluster_itt.independent_cluster_n == 2
    assert result.cluster_itt.treatment_n == result.cluster_itt.control_n == 6
    assert result.treatment_coverage.assigned_n == result.control_coverage.assigned_n == 6
    assert result.population_freeze_manifest_id == (
        experiment.population.population_freeze_manifest_id
    )
    assert result.provenance_closed_coverage_manifest_id == (
        experiment.closed_coverage.provenance_closed_coverage_manifest_id
    )
    assert result.assignment_coverage_manifest_id == (
        experiment.closed_coverage.base_coverage.assignment_coverage_manifest_id
    )
    assert result.simultaneous_confirmation_allowed is False
    assert result.analysis_result_id.startswith("manifest_bound_itt_v2_")

    with pytest.raises(TypeError):
        estimate_manifest_bound_cluster_itt_v2(
            population=experiment.population,
            assignment_coverage=experiment.closed_coverage,
            model_id="model.alpha",
            outcome_name="y_c",  # type: ignore[call-arg]
        )
    with pytest.raises(TypeError):
        estimate_manifest_bound_cluster_itt_v2(
            population=experiment.population,
            assignment_coverage=experiment.closed_coverage,
            model_id="model.alpha",
            treatment_arm=ArmRole.NOOP_REWRITE,  # type: ignore[call-arg]
            control_arm=ArmRole.TARGET_PATCH,
        )


def test_public_itt_entrypoint_rejects_rehashed_population_not_bound_to_coverage() -> None:
    experiment = _authenticated_experiment()
    changed = _without_content_id(experiment.population, "population_freeze_manifest_id")
    changed["population_construction_sha256"] = _sha("different-population-construction")
    rehashed_population = PopulationFreezeManifestV2.from_content(**changed)

    with pytest.raises(ValueError, match="manifest-bound v2 ITT failed exact validation"):
        estimate_manifest_bound_cluster_itt_v2(
            population=rehashed_population,
            assignment_coverage=experiment.closed_coverage,
            model_id="model.alpha",
        )


@pytest.mark.milestone
def test_randomization_runtime_outcome_coverage_and_itt_replay_end_to_end() -> None:
    population = _synthetic_population().manifest
    randomization = _randomization(population)
    committed = tuple(
        _committed_assignment(unit, randomization) for unit in randomization.assignments
    )
    bundles = {
        bundle.task_realization_bundle_id: bundle
        for gate in population.task_gates
        if gate.task_policy_support is not None
        for bundle in gate.task_policy_support.task_realization_bundles
    }
    outcomes = []
    for unit, assignment in zip(randomization.assignments, committed, strict=True):
        bundle = bundles[unit.block.task_realization_bundle_id]
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
        request = GenerationRequestRecordV2.from_content(
            **coordinates,
            prompt_id=variant.variant_prompt_id,
            prompt=variant.prompt_text,
            prompt_sha256=variant.prompt_sha256,
            language="python",
            endpoint_sha256=_sha("synthetic-endpoint"),
            generation_parameters_sha256=unit.generation_parameters_sha256,
            system_template_sha256=_sha("synthetic-system-template"),
            generator_producer_id="generator.synthetic",
            generator_policy_sha256=_sha("generator-policy"),
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
            generator_runtime_sha256=_sha("generator-runtime"),
        )
        target = unit.assigned_arm is ArmRole.TARGET_PATCH
        oracle = OracleResultRecordV2.from_content(
            **coordinates,
            generated_code_id=code.generated_code_id,
            code_sha256=code.code_sha256,
            status="secure" if target else "insecure",
            oracle_supported=True,
            oracle_evaluable=True,
            evidence_sha256=_sha(f"oracle-evidence:{unit.assignment_id}"),
            oracle_producer_id="oracle.synthetic",
            oracle_policy_sha256=_sha("oracle-policy"),
            oracle_runtime_sha256=_sha("oracle-runtime"),
        )
        functional = FunctionalResultRecordV2.from_content(
            **coordinates,
            generated_code_id=code.generated_code_id,
            code_sha256=code.code_sha256,
            status="pass",
            evidence_sha256=_sha(f"functional-evidence:{unit.assignment_id}"),
            evaluator_producer_id="functional.synthetic",
            evaluator_policy_sha256=_sha("functional-policy"),
            evaluator_runtime_sha256=_sha("functional-runtime"),
        )
        outcomes.append(
            assemble_assignment_outcome_v2(
                assignment,
                bundle,
                request,
                code,
                oracle,
                functional,
            )
        )

    coverage = AssignmentCoverageManifestV2.from_components(
        randomization=randomization,
        committed_assignments=committed,
        outcomes=tuple(outcomes),
    )
    authenticated = _authenticated_experiment()
    result = estimate_manifest_bound_cluster_itt_v2(
        population=population,
        assignment_coverage=authenticated.closed_coverage,
        model_id="model.alpha",
    )

    assert coverage.complete is True
    assert coverage.expected_count == 48
    assert result.cluster_itt.estimate == pytest.approx(1.0)
    assert result.treatment_coverage.all_assignment_evaluable_yield == 1.0
    assert result.control_coverage.all_assignment_evaluable_yield == 1.0


@pytest.mark.reviewer
def test_execution_receipts_close_generation_policy_and_outcome_provenance() -> None:
    experiment = _authenticated_experiment()
    closed = experiment.closed_coverage

    assert closed.complete is True
    assert closed.receipt_count == closed.base_coverage.expected_count == 48
    assert closed.assignment_ids == tuple(
        sorted(unit.assignment_id for unit in experiment.randomization.assignments)
    )
    assert (
        ProvenanceClosedAssignmentCoverageManifestV2.model_validate_json(closed.model_dump_json())
        == closed
    )

    with pytest.raises(ValidationError, match="execution v2 contract failed validation"):
        ProvenanceClosedAssignmentCoverageManifestV2.from_receipts(
            execution_policy_freeze=experiment.execution_freeze,
            outcome_assembly_receipts=experiment.receipts[:-1],
        )


def test_execution_receipt_rejects_generation_policy_drift_and_fabricated_outcome() -> None:
    population = _synthetic_population().manifest
    randomization = _randomization(population)
    execution_freeze = _execution_freeze(randomization)
    bundles = {
        bundle.task_realization_bundle_id: bundle
        for gate in population.task_gates
        if gate.task_policy_support is not None
        for bundle in gate.task_policy_support.task_realization_bundles
    }
    unit = next(
        item for item in randomization.assignments if item.assigned_arm is ArmRole.NOOP_REWRITE
    )
    assignment = _committed_assignment(unit, randomization)
    bundle = bundles[unit.block.task_realization_bundle_id]

    with pytest.raises(ValidationError, match="execution v2 contract failed validation"):
        _authenticated_outcome_receipt(
            unit=unit,
            assignment=assignment,
            bundle=bundle,
            execution_freeze=execution_freeze,
            generation_parameters_sha256=_sha("post-hoc-generation-parameters"),
        )

    genuine = _authenticated_outcome_receipt(
        unit=unit,
        assignment=assignment,
        bundle=bundle,
        execution_freeze=execution_freeze,
    )
    assert genuine.outcome.state is AssignmentOutcomeStateV2.VALID_ORACLE_INSECURE
    forged_content = genuine.model_dump(
        mode="python", exclude={"outcome_assembly_receipt_id", "schema_version"}
    )
    forged_content["outcome"] = _outcome(unit)
    with pytest.raises(ValidationError, match="execution v2 contract failed validation"):
        OutcomeAssemblyReceiptV2.from_content(**forged_content)

    drifted_oracle_content = genuine.oracle_result.model_dump(
        mode="python", exclude={"oracle_result_id", "schema_version"}
    )
    drifted_oracle_content["oracle_policy_sha256"] = _sha("post-hoc-oracle-policy")
    drifted_oracle = OracleResultRecordV2.from_content(**drifted_oracle_content)
    with pytest.raises(ValidationError, match="execution v2 contract failed validation"):
        OutcomeAssemblyReceiptV2.from_runtime(
            assignment_execution_receipt=genuine.assignment_execution_receipt,
            generated_code=genuine.generated_code,
            syntax_validation=genuine.syntax_validation,
            oracle_result=drifted_oracle,
            functional_result=genuine.functional_result,
        )

    false_invalid_syntax = SyntaxValidationReceiptV2.from_generated_code(
        generated_code=genuine.generated_code,
        language="python",
        status="invalid",
        parser_producer_id="parser.synthetic",
        parser_policy_sha256=_sha("parser-policy:synthetic"),
        parser_runtime_sha256=_sha("parser-runtime:synthetic"),
        evidence_sha256=_sha("false-invalid-syntax"),
    )
    with pytest.raises(ValidationError, match="execution v2 contract failed validation"):
        OutcomeAssemblyReceiptV2.from_runtime(
            assignment_execution_receipt=genuine.assignment_execution_receipt,
            generated_code=genuine.generated_code,
            syntax_validation=false_invalid_syntax,
            oracle_result=genuine.oracle_result,
            functional_result=genuine.functional_result,
        )


def test_non_null_provider_seed_survives_the_authenticated_chain() -> None:
    population = _synthetic_population().manifest
    randomization = _randomization_with_provider_seeds(population)
    execution_freeze = _execution_freeze(randomization)
    unit = randomization.assignments[0]
    assignment = _committed_assignment(unit, randomization)
    bundle = next(
        bundle
        for gate in population.task_gates
        if gate.task_policy_support is not None
        for bundle in gate.task_policy_support.task_realization_bundles
        if bundle.task_realization_bundle_id == unit.block.task_realization_bundle_id
    )
    receipt = _authenticated_outcome_receipt(
        unit=unit,
        assignment=assignment,
        bundle=bundle,
        execution_freeze=execution_freeze,
    )

    assert unit.provider_seed is not None
    assert assignment.provider_seed == unit.provider_seed
    assert receipt.assignment_execution_receipt.generation_request.provider_seed == (
        unit.provider_seed
    )
    assert receipt.outcome.provider_seed == unit.provider_seed


@pytest.mark.reviewer
def test_total_accounting_preserves_terminal_infrastructure_failure_without_regeneration() -> None:
    experiment = _authenticated_experiment()
    failed = experiment.receipts[-1]
    failure = InfrastructureFailureReceiptV2.from_attempts(
        assignment_execution_receipt=failed.assignment_execution_receipt,
        retry_policy_sha256=_sha("retry-policy:synthetic"),
        attempts=(
            RetryAttemptReceiptV2(
                attempt_index=0,
                stage="provider_transport",
                status="terminal_failure",
                attempt_evidence_sha256=_sha("transport-terminal-failure"),
                provider_response_sha256=None,
                valid_response_persisted=False,
            ),
        ),
        valid_response_lost=False,
    )

    accounting = TotalAssignmentAccountingManifestV2.from_terminal_receipts(
        execution_policy_freeze=experiment.execution_freeze,
        outcome_assembly_receipts=experiment.receipts[:-1],
        infrastructure_failure_receipts=(failure,),
    )

    assert accounting.complete is True
    assert accounting.outcome_count == 47
    assert accounting.failure_count == 1
    assert accounting.confirmatory_coverage is None
    assert failure.regeneration_forbidden is True

    with pytest.raises(ValidationError, match="execution v2 contract failed validation"):
        TotalAssignmentAccountingManifestV2.from_terminal_receipts(
            execution_policy_freeze=experiment.execution_freeze,
            outcome_assembly_receipts=experiment.receipts[:-1],
            infrastructure_failure_receipts=(),
        )

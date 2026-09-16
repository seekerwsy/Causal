"""Seven-stage reviewer smoke and bounded non-claim development execution.

The formal provider runner remains deliberately unavailable while the
prospective protocol is ``SPECIFIED_DRAFT``.  This module executes the exact
scientific stage functions on a deterministic, zero-network fixture and emits
an independently replayable ``NON_CLAIM_TEST_ARTIFACT``.  It is the smallest
representative proof that the target path closes without treating a test run as
study evidence. Authorized development uses the same operation-bound renderer,
measurement and outcome functions, with its separate frozen descriptive analysis.
"""

from __future__ import annotations

from pathlib import Path
from dataclasses import asdict
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import json
import random
import sys

from prompt_mechanism_study.artifact_io import bundle_digest, read_json, write_bundle
from prompt_mechanism_study.reviewer_fixture import load_reviewer_smoke_fixture
from prompt_mechanism_study.measurement import close_target_measurements, measure_generated_code
from prompt_mechanism_study.target_security_profiles import evaluate_target_security_profile
from prompt_mechanism_study.inference import (
    EvidenceLevel,
    build_target_selector_yields,
    estimate_target_itt,
    freeze_assigned_arm_evidence,
)
from prompt_mechanism_study.randomization import (
    TargetRandomizationPlan,
    randomize_target_confirmation,
)
from prompt_mechanism_study.interaction_selector import (
    freeze_pair_preoutcome_design,
    pair_preoutcome_observations,
    run_pair_shadow_qualification,
)
from prompt_mechanism_study.outcomes import derive_outcomes
from prompt_mechanism_study.prioritization import (
    FixedSlotSource,
    PolicyTrack,
    atomic_preoutcome_observations,
    freeze_atomic_candidate_folds,
    freeze_confirmation_dispatch,
    freeze_fixed_slot_ledger,
    freeze_shared_confirmation_union,
    run_atomic_shadow_qualification,
)
from prompt_mechanism_study.records import content_hash, content_id
from prompt_mechanism_study.representation import (
    DataRole,
    validate_data_role_firewall,
)
from prompt_mechanism_study.selector_analysis import write_target_result_bundle
from prompt_mechanism_study.verification import (
    verify_target_study_freezes,
)
from prompt_mechanism_study.study_design import (
    freeze_target_confirmation_design,
    freeze_target_discovery_design,
    freeze_target_study_index,
    validate_formal_budget_preflight,
)
from prompt_mechanism_study.study_planning import FreezeArtifactReference
from prompt_mechanism_study.task_input import prepare_task_input, generation_input_for_prompt


PROTOCOL_ID = "phase-context-policy-v3"
SCHEMA_VERSION = "3.0"
SMOKE_MODEL_ID = "reviewer-smoke-model"
DEVELOPMENT_CODE_RESPONSE_FORMAT = {"type": "json_schema", "json_schema": {
    "name": "generated_python_code", "strict": True,
    "schema": {"type": "object", "additionalProperties": False,
               "properties": {"code": {"type": "string"}}, "required": ["code"]}}}
SMOKE_STAGES = (
    "representation",
    "prioritization",
    "hypothesis_freeze",
    "intervention_randomization",
    "measurement",
    "outcome_assembly",
    "inference_reporting",
)


def prepare_development_assignments(plan: dict) -> list[dict]:
    """Replay source-reviewed operation bindings before any development generation.

    This tests measurement and intervention behavior; it does not execute Discovery,
    select hypotheses from outcomes, assign formal roles, or activate the protocol.
    """
    from prompt_mechanism_study.mechanisms import bind_task_hypothesis, render_task_hypothesis
    from prompt_mechanism_study.prompt_tsg import prompt_tsg_from_record, validate_prompt_tsg
    from prompt_mechanism_study.target_security_profiles import target_security_profile_producer_sha256

    if (plan.get("status") != "FROZEN_NON_CLAIM_DEVELOPMENT"
            or plan.get("scientific_claim_allowed") is not False
            or plan.get("qualification_accept_consumed") is not False
            or plan.get("formal_execution_authorized") is not False):
        raise ValueError("only an explicitly bounded non-claim development plan is executable")
    if plan["security_producer_sha256"] != target_security_profile_producer_sha256():
        raise ValueError("development security producer differs from its prospective freeze")
    tasks = plan["tasks"]
    if len({task["task_unit_id"] for task in tasks}) != len(tasks):
        raise ValueError("development inputs must be deduplicated task units")
    if sorted(task["task_id"] for task in tasks) != sorted(plan["development_exposed_task_ids"]):
        raise ValueError("every task needs recorded development exposure before generation")
    seeds = plan["generation_seeds"]
    arms = plan["arms"]
    if (not seeds or len(set(seeds)) != len(seeds) or any(type(seed) is not int for seed in seeds)
            or arms not in (["BASELINE", "NOOP", "STYLE", "GENERIC", "TARGET"],
                            ["NOOP", "STYLE", "GENERIC", "TARGET"], ["A00", "A10", "A01", "A11"])):
        raise ValueError("development requires a complete Atomic or Pair arm family and unique generation seeds")
    if plan["maximum_provider_calls"] != 2 * len(tasks) * len(seeds) * len(arms):
        raise ValueError("development call ceiling must cover every generation and functional review")
    if any(evaluator.get("max_attempts") != 1 for evaluator in (plan["generator"], plan["functional_evaluator"])):
        raise ValueError("development has one prospective attempt and no outcome-driven replacements")
    if plan["generator"].get("response_format") != DEVELOPMENT_CODE_RESPONSE_FORMAT:
        raise ValueError("development code generation requires the strict code-only JSON response contract")
    policies = {row["policy_id"]: row for row in plan["policies"]}
    assignments = []
    for task in tasks:
        if "generation_input" not in task:
            raise ValueError("prepare task input and re-extract its TSG before development generation")
        task = prepare_task_input(task, generation_system_prompt=plan["generation_system_prompt"])
        if task["language"] != "python" or task["prompt_sha256"] != content_hash(task["prompt"]):
            raise ValueError("development source identity or language changed")
        graph = prompt_tsg_from_record(task["graph"])
        validate_prompt_tsg(graph, prompt=task["prompt"], catalog=plan["catalog"])
        if task["functional_contract"].get("source_prompt_sha256") != task["prompt_sha256"]:
            raise ValueError("functional contract must bind the same prepared baseline input")
        policy = policies[task["policy_id"]]
        subject_id = task.get("target_subject_node_id")
        binding, prompts = _development_prompts(task, policy, graph, plan["catalog"], arms)
        if binding.binding_id != task["binding_id"]:
            raise ValueError("development task-hypothesis binding changed")
        for seed in seeds:
            for arm in arms:
                generation_input_for_prompt(task, prompts[arm])
                row = {"task_id": task["task_id"], "task_unit_id": task["task_unit_id"],
                       "policy_id": policy["policy_id"], "binding_id": binding.binding_id,
                       "target_operation_node_id": binding.target_operation_node_id,
                       "arm": arm, "seed": seed, "prompt": prompts[arm],
                       "prompt_sha256": content_hash(prompts[arm]), "security_profile_id": policy["security_profile_id"]}
                if binding.factor_scopes:
                    row["factor_scopes"] = task["factor_scopes"]
                if subject_id is not None:
                    row["target_subject_node_id"] = subject_id
                row["assignment_id"] = content_id("development_assignment_", row)
                assignments.append(row)
    random.Random(plan["randomization_seed"]).shuffle(assignments)
    return assignments


def _development_prompts(task, policy, graph, catalog, arms):
    """Use the same exact factor binding for every assigned treatment and control."""
    from prompt_mechanism_study.mechanisms import bind_task_hypothesis, render_task_hypothesis
    from prompt_mechanism_study.prompt_tsg import feature_scope_from_record, FeatureScope
    factors = policy["factors"] if "factors" in policy else [{**policy, "operation": "add"}]
    pair = len(factors) == 2
    if len(factors) not in (1, 2) or pair != (arms == ["A00", "A10", "A01", "A11"]):
        raise ValueError("development factors and arm family differ")
    for factor in factors:
        definition = factor.get("factor_definition", {})
        if not task.get("factor_scopes"):
            if arms != ["BASELINE", "NOOP", "STYLE", "GENERIC", "TARGET"]:
                raise ValueError("new development arms require exact factor scopes")
            if task.get("target_subject_node_id") is None:
                continue
            if not definition.get("subject_role"):
                raise ValueError("subject-bound development requires a single-requirement subject role")
        if (definition.get("semantic_decisions") != [factor["feature_id"]]
            or definition.get("atomicity_review") != "SOURCE_REVIEWED_SINGLE_REQUIREMENT"
            or (task.get("factor_scopes") and not definition.get("scope_rule")) or not definition.get("definition")):
            raise ValueError("scoped development needs a reviewed single-requirement definition and scope rule")
    coordinates = {"factor_scopes": tuple(feature_scope_from_record(row) for row in task["factor_scopes"])} if task.get("factor_scopes") else {
        "target_operation_node_id": task["target_operation_node_id"],
        "factor_subject_node_ids": (task["target_subject_node_id"],) if task.get("target_subject_node_id") else ()}
    binding = bind_task_hypothesis(graph, query=policy["query"], policy_id=policy["policy_id"],
        factor_feature_ids=tuple(factor["feature_id"] for factor in factors),
        factor_operations=tuple(factor["operation"] for factor in factors), **coordinates)
    if task.get("factor_scopes"):
        compatibility = task.get("intervention_compatibility", task.get("pair_compatibility", {}))
        if (compatibility.get("binding_id") != binding.binding_id
            or compatibility.get("decision") != "compatible"
            or compatibility.get("outcomes_used") is not False
            or not compatibility.get("rationale")):
            raise ValueError("scoped development needs source-reviewed intervention compatibility; Pair requires independent four-cell compatibility")
    by_node = {node.node_id: node for node in graph.nodes}
    task_start = len(task["prompt"]) - len(task["generation_input"]["request"]["task"])
    scopes = binding.factor_scopes or (FeatureScope(binding.target_operation_node_id),)
    if any(by_node[scope.operation_node_id].evidence_start < task_start for scope in scopes):
        raise ValueError("development factors must bind operations in the user task")
    controls = task["factor_control_texts"] if "factor_control_texts" in task else [task["control_texts"]]
    if len(controls) != len(factors):
        raise ValueError("development requires frozen controls for each scoped factor")
    flags = {"A00": (False, False), "A10": (True, False), "A01": (False, True), "A11": (True, True)} if pair else {
        "BASELINE": (False,), "NOOP": (False,), "STYLE": (False,), "GENERIC": (False,), "TARGET": (True,)}
    prompts = {}
    for arm in arms:
        if arm == "BASELINE":
            prompts[arm] = task["prompt"]
            continue
        inactive = {factor["feature_id"]: controls[index]["NOOP" if pair else arm]
                    for index, factor in enumerate(factors) if not flags[arm][index]}
        rendered = render_task_hypothesis(binding, graph, prompt=task["prompt"], catalog=catalog,
            enabled=flags[arm], additions={factor["feature_id"]: factor["addition"]
                for factor in factors if factor["operation"] == "add"},
            inactive_texts=inactive, reviewed_variant=task.get("reviewed_variants", {}).get(arm))
        prompts[arm] = rendered["prompt"]
    if not pair:
        factor = factors[0]
        if factor["operation"] == "add":
            target_words = len(factor["addition"].split())
        else:
            # The reviewed placebo matches the predeclared removed requirement,
            # not a retrospectively chosen length of generated code.
            from prompt_mechanism_study.prompt_tsg import scoped_feature_assessment
            assessment = scoped_feature_assessment(graph, factor["feature_id"], binding.factor_scopes[0])
            target_words = sum(len(task["prompt"][by_node[key].evidence_start:by_node[key].evidence_end].split())
                               for key in assessment.requirement_node_ids)
        if len(controls[0]["STYLE"].split()) != target_words:
            raise ValueError("style control must match the frozen requirement whitespace-word length")
    return binding, prompts


def run_target_development(plan_path: Path, output: Path, *, complete=None) -> dict:
    """Run one prospectively frozen development comparison through actual measurement.

    Exact source/arm/seed assignments are saved before provider calls. Raw responses
    and failures survive independently of final analysis. No task is replaced.
    """
    from prompt_mechanism_study.functional_judge import bailian_complete
    from prompt_mechanism_study.inference import summarize_development_itt, summarize_development_sampling
    from prompt_mechanism_study.measurement import MeasurementLedger

    plan = read_json(plan_path)
    assignments = prepare_development_assignments(plan)
    provider = complete or bailian_complete
    if output.exists():
        raise FileExistsError(output)
    output.mkdir(parents=True)
    write_bundle(output / "preoutcome", {"plan.json": plan, "assignments.json": assignments,
        "environment.json": {"python": sys.version, "platform": sys.platform,
                             "security_producer_sha256": plan["security_producer_sha256"]}})
    task_by_id = {task["task_id"]: task for task in plan["tasks"]}

    def measure(row):
        calls = []
        def captured(request, evaluator, prompt):
            attempt = {"request": request, "evaluator": dict(evaluator), "system_prompt": prompt}
            calls.append(attempt)
            try:
                raw = provider(request, evaluator, prompt)
                attempt["response"] = raw.decode("utf-8")
                return raw
            except Exception as error:
                attempt["error"] = f"{type(error).__name__}: {error}"
                raise
        task = task_by_id[row["task_id"]]
        result = dict(row, code=None, code_valid=None, security_status=None, functionality_status=None,
                      secure_code_yield=None, oracle_evaluable=None, functionality=None, joint=None,
                      measurement_evidence=None, error=None)
        try:
            generation_input = generation_input_for_prompt(task, row["prompt"])
            measurement, evidence = measure_generated_code(
                assignment_id=row["assignment_id"],
                generation_request=generation_input["request"],
                generation_evaluator={**plan["generator"], "seed": row["seed"]},
                generation_prompt=generation_input["system_prompt"], source_task_prompt=task["prompt"],
                functional_contract=task["functional_contract"],
                functional_evaluator=plan["functional_evaluator"], functional_prompt=plan["functional_system_prompt"],
                security_profile_id=row["security_profile_id"], complete=captured,
                security_evaluate=evaluate_target_security_profile)
            outcome = derive_outcomes(MeasurementLedger(plan["run_id"], content_hash(assignments),
                                      "non_claim_development", (measurement,)))[0]
            result.update(code=evidence["code"], code_valid=outcome.code_valid,
                          security_status=measurement.oracle_status.value,
                          functionality_status=measurement.functional_status.value,
                          secure_code_yield=outcome.secure_yield, oracle_evaluable=outcome.oracle_evaluable,
                          functionality=outcome.functionality, joint=outcome.joint,
                          measurement_evidence=evidence, measurement=asdict(measurement), outcome=asdict(outcome))
        except Exception as error:
            result["error"] = f"{type(error).__name__}: {error}"
            # Preserve a successful generation even when later measurement failed.
            if calls and "response" in calls[0]:
                try:
                    result["code"] = json.loads(calls[0]["response"]).get("code")
                except (ValueError, AttributeError):
                    pass
        result["provider_calls"] = len(calls)
        result["provider_calls_by_kind"] = dict(Counter(call['evaluator'].get('provider', 'unspecified') for call in calls))
        write_bundle(output / "cases" / row["assignment_id"], {"calls.json": calls, "result.json": result})
        print(json.dumps({"assignment_id": row["assignment_id"], "status": "FAILED" if result["error"] else "MEASURED"}), flush=True)
        return result

    with ThreadPoolExecutor(max_workers=plan["workers"]) as pool:
        rows = list(pool.map(measure, assignments))
    effects = summarize_development_itt(rows, plan["analysis"])
    provider_kinds = Counter()
    for row in rows:
        provider_kinds.update(row['provider_calls_by_kind'])
    report = {"status": "NON_CLAIM_DEVELOPMENT_COMPLETE" if complete is None else "OFFLINE_REPLAY_NON_CLAIM_DEVELOPMENT_COMPLETE", "scientific_claim_allowed": False,
              "evidence_level": "executed_development" if complete is None else "replayed_development", "run_id": plan["run_id"],
              "plan_sha256": content_hash(plan), "preoutcome_bundle_sha256": bundle_digest(output / "preoutcome"),
              "task_units": len(task_by_id), "assigned_rows": len(assignments),
              "measured_rows": sum(row["error"] is None for row in rows),
              "failed_rows": sum(row["error"] is not None for row in rows),
              "provider_calls": sum(row["provider_calls"] for row in rows),
              "external_provider_calls": sum(row["provider_calls"] for row in rows) if complete is None else 0,
              "live_provider_calls_by_kind": dict(provider_kinds) if complete is None else {},
              "response_source": "live_provider" if complete is None else "offline_supplied_responses",
              "functional_evaluator_failures": sum(bool((row["measurement_evidence"] or {}).get("functional_failure")) for row in rows),
              "denominator": "all assigned deduplicated task units; seeds averaged within each task",
              "uncertainty": "Development paired sign-flip tests and task bootstrap intervals; no confirmatory claim or selector validation.",
              "security_counts": dict(Counter(row["security_status"] or "infrastructure_failure" for row in rows)),
              "functional_counts": dict(Counter(row["functionality_status"] or "infrastructure_failure" for row in rows)),
              "pair_status": ("DEVELOPMENT_FOUR_CELL_EXECUTED" if complete is None else "DEVELOPMENT_FOUR_CELL_OFFLINE_REPLAY")
                  if plan["arms"] == ["A00", "A10", "A01", "A11"] else "NOT_EXECUTED_NO_FROZEN_NATURAL_FOUR_CELL_SUPPORT",
              "context_modifier_status": "BLOCKED_NO_FROZEN_CONTEXT_RULE"}
    if plan["arms"] == ["A00", "A10", "A01", "A11"]:
        report.update(pair_natural_support_status="NOT_ESTABLISHED_BY_INTERVENTION_CELLS",
                      pair_response_pattern_status="BLOCKED_NO_FROZEN_JOINT_RULE",
                      uncertainty="Descriptive four-cell task contrasts and marginal task bootstrap intervals; no Pair null test or response-pattern claim.")
    write_bundle(output / "summary", {"report.json": report, "effects.json": effects, "assignments.json": rows,
                                     "sampling.json": summarize_development_sampling(rows, plan['analysis'])})
    return report


def run_target_reviewer_smoke(output: Path) -> dict[str, object]:
    """Traverse the seven target stages once without network calls or claims."""

    if not isinstance(output, Path):
        raise TypeError("target reviewer smoke output must be a Path")

    # Stage 1: representation and the pre-discovery design boundary.
    inputs = load_reviewer_smoke_fixture()
    manifest = inputs.manifest
    firewall = validate_data_role_firewall(
        manifest,
        {
            "DISCOVERY-SMOKE": DataRole.DISCOVERY,
            "CONFIRMATION-SMOKE": DataRole.CONFIRMATION,
        },
    )
    budget = inputs.budget
    population_lineage = inputs.population_lineage
    atomic_folds = freeze_atomic_candidate_folds(
        inputs.atomic_universe,
        atomic_preoutcome_observations(inputs.atomic_observations),
        inputs.atomic_plan,
    )
    pair_preoutcome = freeze_pair_preoutcome_design(
        inputs.pair_universe,
        pair_preoutcome_observations(inputs.pair_observations),
        inputs.pair_plan,
    )
    discovery = freeze_target_discovery_design(
        schema_version=SCHEMA_VERSION,
        manifest=manifest,
        qualification_bundle=budget.qualification_bundle,
        budget=budget,
        population_lineage=population_lineage,
        atomic_discovery_population_sha256=(
            inputs.atomic_universe.discovery_population_sha256
        ),
        pair_discovery_population_sha256=(
            inputs.pair_universe.discovery_population_sha256
        ),
        identity_and_scope_decision=_artifact_reference(
            "reviewer_smoke_identity_scope_",
            (inputs.atomic_policy, inputs.pair_policy),
        ),
        candidate_universe_contract=_artifact_reference(
            "reviewer_smoke_candidate_universes_",
            (inputs.atomic_universe, inputs.pair_universe),
        ),
        support_gate_contract=_artifact_reference(
            "reviewer_smoke_support_gates_",
            (
                inputs.atomic_universe.supported_policy_keys,
                pair_preoutcome.support_gates,
            ),
        ),
        discoverability_contract=_artifact_reference(
            "reviewer_smoke_discoverability_",
            (atomic_folds.discoverability, pair_preoutcome.discoverability),
        ),
        candidate_fold_manifests=_artifact_reference(
            "reviewer_smoke_candidate_folds_",
            (atomic_folds, pair_preoutcome),
        ),
        selector_contract=_artifact_reference(
            "reviewer_smoke_selector_contracts_",
            (inputs.atomic_plan, inputs.pair_plan),
        ),
        discovery_outcome_contract=_artifact_reference(
            "reviewer_smoke_discovery_outcome_",
            "oracle_evaluable_secure_code_yield",
        ),
    )

    # Stage 2: both sole-difference Core selector pairs consume the frozen folds.
    atomic_fci_evidence = inputs.atomic_fci_evidence
    pair_relation_evidence = inputs.pair_relation_evidence
    atomic = run_atomic_shadow_qualification(
        inputs.atomic_universe,
        inputs.atomic_observations,
        inputs.atomic_plan,
        atomic_fci_evidence,
        fold_freeze=atomic_folds,
    )
    pair = run_pair_shadow_qualification(
        inputs.pair_universe,
        inputs.pair_observations,
        pair_relation_evidence,
        inputs.pair_plan,
        preoutcome_freeze=pair_preoutcome,
    )
    sources = (
        FixedSlotSource(
            PolicyTrack.ATOMIC,
            "atomic_full",
            SMOKE_MODEL_ID,
            inputs.atomic_universe.universe_id,
            atomic.full.slots,
            inputs.atomic_universe.model_bound_records,
        ),
        FixedSlotSource(
            PolicyTrack.ATOMIC,
            "atomic_rd_only",
            SMOKE_MODEL_ID,
            inputs.atomic_universe.universe_id,
            atomic.rd_only.slots,
            inputs.atomic_universe.model_bound_records,
        ),
        FixedSlotSource(
            PolicyTrack.PAIR,
            "pair_full",
            SMOKE_MODEL_ID,
            inputs.pair_universe.universe_id,
            pair.full.slots,
            inputs.pair_universe.model_bound_records,
        ),
        FixedSlotSource(
            PolicyTrack.PAIR,
            "pair_no_relation",
            SMOKE_MODEL_ID,
            inputs.pair_universe.universe_id,
            pair.no_relation.slots,
            inputs.pair_universe.model_bound_records,
        ),
    )

    # Stage 3: fixed slots, one shared union, and one protocolization per policy.
    ledger = freeze_fixed_slot_ledger(PROTOCOL_ID, SCHEMA_VERSION, sources)
    union = freeze_shared_confirmation_union(ledger)
    protocol_records = {
        entry.candidate_record_id: content_id(
            "reviewer_smoke_protocol_record_",
            entry.candidate.policy_key,
        )
        for entry in union.entries
    }
    dispatch = freeze_confirmation_dispatch(union, protocol_records)

    # Stage 4: model-bound complete blocks and the second, pre-outcome freeze.
    randomization_plan = TargetRandomizationPlan(
        PROTOCOL_ID,
        SCHEMA_VERSION,
        2026083107,
        2026083108,
        budget.dimensions.atomic_total_block_slots,
        budget.dimensions.pair_total_block_slots,
        tuple(sorted((entry.candidate.policy_key, "reviewer-smoke-realization-1", 1.0)
                     for entry in union.entries)),
        tuple(sorted((entry.candidate.policy_key, f"{entry.track.value}-smoke-task-{index:02d}",
                      "reviewer-smoke-stratum") for entry in union.entries for index in range(10))),
    )
    task_bundles = inputs.task_bundles(dispatch, randomization_plan)
    assignments = randomize_target_confirmation(
        dispatch,
        randomization_plan,
        task_bundles,
    )
    preflight = validate_formal_budget_preflight(budget, dispatch, assignments)
    confirmation = freeze_target_confirmation_design(
        discovery=discovery,
        budget=budget,
        ledger=ledger,
        union=union,
        dispatch=dispatch,
        randomization_plan=randomization_plan,
        task_bundles=task_bundles,
        assignments=assignments,
        preflight=preflight,
        outcome_contract=_artifact_reference(
            "reviewer_smoke_confirmation_outcome_",
            "assigned_arm_task_unit_itt_v1",
        ),
    )
    index = freeze_target_study_index(discovery, confirmation)
    freeze_verification = verify_target_study_freezes(
        manifest=manifest,
        budget=budget,
        discovery=discovery,
        ledger=ledger,
        union=union,
        dispatch=dispatch,
        randomization_plan=randomization_plan,
        task_bundles=task_bundles,
        assignments=assignments,
        preflight=preflight,
        confirmation=confirmation,
        index=index,
    )

    # Stage 5: raw offline responses traverse the actual measurement sequence.
    measurements = []
    evaluator = {"model_id": SMOKE_MODEL_ID}
    for assignment in assignments:
        prompt = inputs.variant_prompt(assignment.policy_key, assignment.task_unit_id, assignment.arm.value)
        if content_hash(prompt) != assignment.variant_sha256:
            raise ValueError("smoke generation prompt drifted from its assignment")
        request = {
            "model_id": assignment.model_id, "arm": assignment.arm.value,
            "task_unit_id": assignment.task_unit_id, "task_instance_id": assignment.task_instance_id,
            "provider_seed": assignment.provider_seed, "prompt": prompt,
        }
        measured, _ = measure_generated_code(
            assignment_id=assignment.assignment_id,
            generation_request=request, generation_evaluator=evaluator, generation_prompt=prompt,
            source_task_prompt=inputs.source_task_prompt,
            functional_contract={
                "requirements": [{"requirement_id": "fetch", "criterion": inputs.functional_requirement}],
                "environment_dependencies": [], "language": "python",
            },
            functional_evaluator=evaluator, functional_prompt="Blinded functional review.",
            security_profile_id=inputs.security_profile_id,
            complete=inputs.complete, security_evaluate=evaluate_target_security_profile,
        )
        measurements.append(measured)
    measurement_ledger = close_target_measurements(
        assignments,
        measurements,
        study_id=content_id("target_reviewer_smoke_study_", index),
        randomization_id=randomization_plan.target_randomization_plan_id,
        adapter_bundle_id=content_id("target_reviewer_smoke_adapters_", "local"),
    )

    # Stage 6: total assigned-arm outcome assembly retains every assignment.
    outcomes = derive_outcomes(measurement_ledger)
    evidence_ledger = freeze_assigned_arm_evidence(
        dispatch,
        assignments,
        outcomes,
    )

    # Stage 7: task-unit ITT, fixed-K tables, exact package, independent replay.
    evidence = estimate_target_itt(
        evidence_ledger,
        budget.power_and_margin_memo.target_itt_plan(),
        evidence_level=EvidenceLevel.TESTED,
    )
    yields = build_target_selector_yields(evidence)
    written = write_target_result_bundle(
        output,
        manifest=manifest,
        budget=budget,
        discovery=discovery,
        ledger=ledger,
        union=union,
        dispatch=dispatch,
        randomization_plan=randomization_plan,
        task_bundles=task_bundles,
        assignments=assignments,
        preflight=preflight,
        confirmation=confirmation,
        index=index,
        evidence=evidence,
        yields=yields,
    )
    return {
        "status": "TARGET_REVIEWER_SMOKE_VERIFIED",
        "protocol_status": "SPECIFIED_DRAFT",
        "schema_version": SCHEMA_VERSION,
        "protocol_id": PROTOCOL_ID,
        "stages": list(SMOKE_STAGES),
        "stage_count": len(SMOKE_STAGES),
        "data_role_firewall_validation_id": firewall["firewall_validation_id"],
        "discovery_design_freeze_id": discovery.discovery_design_freeze_id,
        "confirmation_freeze_id": confirmation.confirmation_freeze_id,
        "study_freeze_index_id": index.study_freeze_index_id,
        "freeze_verification_status": freeze_verification["status"],
        "assignment_count": len(assignments),
        "measurement_count": len(measurement_ledger.measurements),
        "outcome_count": len(outcomes),
        "provider_calls_made": 0,
        "evidence_level": evidence.evidence_level.value,
        "package_status": written["package_status"],
        "scientific_claim_allowed": written["scientific_claim_allowed"],
        "result_bundle_sha256": bundle_digest(output),
    }


def _artifact_reference(prefix: str, value: object) -> FreezeArtifactReference:
    return FreezeArtifactReference(content_id(prefix, value), content_hash(value))

__all__ = ["SMOKE_STAGES", "run_target_reviewer_smoke"]

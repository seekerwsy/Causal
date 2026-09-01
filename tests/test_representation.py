"""Schema-3 identity, scope, and outcome-blind source-gate invariants."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from prompt_mechanism_study.prompt_tsg import QueryState
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.representation import (
    AnalysisScope,
    AtomicPolicyKey,
    ModelBoundCandidateRecord,
    ModelEffectCoordinate,
    Operation,
    PolicyFactor,
    SourceEligibilityDecision,
    freeze_source_eligibility,
    pair_policy_key,
)


ROOT = Path(__file__).parents[1]


@pytest.mark.reviewer
def test_identity_and_scope_author_decision_matches_target_primitives() -> None:
    decision = json.loads(
        (ROOT / "configs/formal/identity_and_scope_decision.json").read_text(
            encoding="utf-8"
        )
    )

    assert decision["protocol_id"] == "phase-context-policy-v3"
    assert decision["status"] == "DECISION_RECORDED"
    assert decision["formal_execution_authorized"] is False
    provider = decision["prospective_provider_policy"]
    assert provider["status"] == (
        "AUTHOR_SELECTED_PENDING_ROLE_QUALIFICATION_AND_TOTAL_COST_CAP"
    )
    assert provider["fixed_snapshot_model_id"] == "qwen3.7-flash-2026-07-15"
    assert provider["deployment_region"] == "cn-beijing"
    assert provider["dynamic_alias_allowed"] is False
    assert provider["fallback_model_ids"] == []
    assert provider["replication_model_ids"] == []
    assert provider["automatic_retry_ceiling"] == 0
    assert provider["qualification"]["formal_use_authorized"] is False
    cost_basis = provider["token_cost_basis"]
    for ceiling in provider["call_ceilings"].values():
        numerator = (
            ceiling["maximum_input_tokens"]
            * cost_basis["input_price_microunits_per_million_tokens"]
            + ceiling["maximum_output_tokens"]
            * cost_basis["output_price_microunits_per_million_tokens"]
        )
        assert ceiling["maximum_call_cost_microunits"] == (
            numerator + 999_999
        ) // 1_000_000
    source_population = decision["prospective_source_population"]
    assert source_population["status"] == (
        "SOURCE_POPULATION_FROZEN_PENDING_REPRESENTATION_QUALIFICATION"
    )
    assert source_population["selection_rule"] == {
        "language": "python",
        "quality_disposition": "QUALITY_INCLUDED",
    }
    assert source_population["task_unit_count"] == 381
    assert source_population["technical_readiness_diagnostic_count"] == 101
    assert source_population["technical_readiness_is_not_an_admission_rule"] is True
    assert source_population["formal_role_assigned_count"] == 0
    assert source_population["prompt_tsg_status"] == (
        "NOT_GENERATED_PENDING_METHOD_FREEZE"
    )
    manifest_path = ROOT / source_population["data_bundle_path"] / "manifest.json"
    assert hashlib.sha256(manifest_path.read_bytes()).hexdigest() == (
        source_population["data_manifest_sha256"]
    )
    assert decision["analysis_scope"]["fields"] == [
        "security_pattern_id",
        "context_query_id",
        "language_scope",
        "api_scope",
        "task_archetype_scope",
    ]
    assert decision["policy_identity"]["model_independent"] is True
    assert decision["model_effect_coordinate"] == ["policy_key", "model_id"]
    assert decision["model_dispatch"]["confirmation_cross_product_models"] is False
    assert (
        decision["realization_allocation"][
            "assignments_per_task_policy_coordinate"
        ]
        == 1
    )


@pytest.mark.extended
def test_frozen_python_source_population_replays_from_reviewer_bundle() -> None:
    decision = json.loads(
        (ROOT / "configs/formal/identity_and_scope_decision.json").read_text(
            encoding="utf-8"
        )
    )["prospective_source_population"]
    bundle = ROOT / decision["data_bundle_path"]
    tasks = {
        row["task_unit_id"]: row
        for row in _jsonl(bundle / "task-units.jsonl")
    }
    quality = {
        row["task_unit_id"]: row
        for row in _jsonl(bundle / "task-quality.jsonl")
    }
    readiness = {
        row["task_unit_id"]: row
        for row in _jsonl(bundle / "readiness-worklist.jsonl")
    }
    rule = decision["selection_rule"]
    task_ids = tuple(
        sorted(
            task_unit_id
            for task_unit_id, task in tasks.items()
            if task["pre_treatment_source_metadata"]["language"] == rule["language"]
            and quality[task_unit_id]["quality_disposition"]
            == rule["quality_disposition"]
        )
    )

    assert len(task_ids) == decision["task_unit_count"]
    assert content_hash(task_ids) == decision["task_unit_id_set_sha256"]
    assert sum(
        readiness[task_unit_id]["readiness_summary_status"]
        == "TECHNICALLY_READY_PENDING_METHOD_FREEZE"
        for task_unit_id in task_ids
    ) == decision["technical_readiness_diagnostic_count"]


def _jsonl(path: Path) -> tuple[dict[str, object], ...]:
    return tuple(
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    )


@pytest.mark.reviewer
@pytest.mark.extended
def test_policy_identity_is_model_independent_and_dispatch_is_model_bound() -> None:
    scope = AnalysisScope(
        "SQL_VALUE_FLOW",
        "context.sql.external_value_reaches_value_slot",
        ("python",),
        ("raw_sql", "supported_db_api"),
        ("database_query",),
    )
    parameterization = PolicyFactor(
        "SQL_PARAMETER_BINDING",
        Operation.ADD,
    )
    atomic = AtomicPolicyKey(
        scope,
        parameterization,
        "oracle_evaluable_secure_code_yield",
    )
    first = ModelEffectCoordinate(atomic.policy_key, "model-a")
    second = ModelEffectCoordinate(atomic.policy_key, "model-b")
    record = ModelBoundCandidateRecord(
        atomic.policy_key,
        "model-a",
        "phase-context-policy-v3",
        "3.0-draft",
    )

    assert first.policy_key == second.policy_key == atomic.policy_key
    assert first.effect_coordinate_id != second.effect_coordinate_id
    assert record.effect_coordinate == first
    assert AtomicPolicyKey(
        scope,
        PolicyFactor("SQL_PARAMETER_BINDING", Operation.REMOVE),
        "oracle_evaluable_secure_code_yield",
    ).policy_key != atomic.policy_key
    assert AtomicPolicyKey(
        scope,
        parameterization,
        "functionality",
    ).policy_key != atomic.policy_key
    assert AtomicPolicyKey(
        AnalysisScope(
            "SQL_VALUE_FLOW",
            "context.sql.external_value_reaches_value_slot",
            ("python",),
            ("raw_sql",),
            ("database_query",),
        ),
        parameterization,
        "oracle_evaluable_secure_code_yield",
    ).policy_key != atomic.policy_key
    assert record.candidate_record_id != ModelBoundCandidateRecord(
        atomic.policy_key,
        "model-a",
        "phase-context-policy-v3",
        "3.1-draft",
    ).candidate_record_id

    allow_listing = PolicyFactor("SQL_IDENTIFIER_ALLOW_LIST", Operation.ADD)
    forward = pair_policy_key(
        scope,
        (parameterization, allow_listing),
        outcome_id="oracle_evaluable_secure_code_yield",
    )
    reverse = pair_policy_key(
        scope,
        (allow_listing, parameterization),
        outcome_id="oracle_evaluable_secure_code_yield",
    )
    assert forward == reverse
    assert forward.policy_key == reverse.policy_key

@pytest.mark.reviewer
@pytest.mark.extended
def test_add_remove_source_gate_preserves_exclusions() -> None:
    prompt = "Implement a database lookup."
    common = {
        "task_id": "task.sql",
        "task_unit_id": "unit.sql",
        "prompt_tsg_id": "prompt-tsg.sql",
        "prompt_sha256": content_hash(prompt),
        "context_state": QueryState.PRESENT,
        "eligibility_policy_sha256": content_hash("source-gate-v3"),
    }

    add = _policy(Operation.ADD)
    add_pass = freeze_source_eligibility(add, feature_state=QueryState.ABSENT, **common)
    add_fail = freeze_source_eligibility(add, feature_state=QueryState.PRESENT, **common)
    assert add_pass.eligible
    assert add_fail.decision is SourceEligibilityDecision.EXCLUDED
    assert add_fail.exclusion_reason == "add_source_present"
    with pytest.raises(ValueError, match="does not satisfy"):
        replace(
            add_fail,
            decision=SourceEligibilityDecision.ELIGIBLE,
            exclusion_reason=None,
        )

    remove = _policy(Operation.REMOVE)
    no_evidence = freeze_source_eligibility(
        remove,
        feature_state=QueryState.PRESENT,
        neutral_counterpart="Keep the functional database lookup requirement.",
        **common,
    )
    no_counterpart = freeze_source_eligibility(
        remove,
        feature_state=QueryState.PRESENT,
        target_evidence_node_ids=("node.guard",),
        **common,
    )
    passed = freeze_source_eligibility(
        remove,
        feature_state=QueryState.PRESENT,
        target_evidence_node_ids=("node.guard",),
        neutral_counterpart="Keep the functional database lookup requirement.",
        **common,
    )
    assert no_evidence.exclusion_reason == "remove_target_evidence_missing"
    assert no_counterpart.exclusion_reason == "remove_neutral_counterpart_missing"
    assert passed.eligible
    assert passed.neutral_counterpart_sha256 == content_hash(
        "Keep the functional database lookup requirement."
    )


def _policy(operation: Operation) -> AtomicPolicyKey:
    return AtomicPolicyKey(
        AnalysisScope(
            "SQL_VALUE_FLOW",
            "context.sql.external_value_reaches_value_slot",
            ("python",),
            ("raw_sql",),
            ("database_query",),
        ),
        PolicyFactor(
            "SQL_PARAMETER_BINDING",
            operation,
        ),
        "oracle_evaluable_secure_code_yield",
    )

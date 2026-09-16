"""Schema-3 identity, scope, and outcome-blind source-gate invariants."""

from __future__ import annotations
from prompt_mechanism_study.representation import (
    AnalysisScope,
    AtomicPolicyKey,
    ModelBoundCandidateRecord,
    ModelEffectCoordinate,
    Operation,
    PolicyFactor,
    pair_policy_key,
)


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

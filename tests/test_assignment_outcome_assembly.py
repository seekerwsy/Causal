from __future__ import annotations

import hashlib
import json

import pytest

from secaware.outcomes.assembler import assemble_assignment_outcomes
from secaware.functional_judge.schema import (
    FunctionalAuditStatus,
    FunctionalJudgeability,
    FunctionalRequirementRecord,
    ProgramFunctionalOutcomeRecord,
    TaskFunctionalContractRecord,
)
from secaware.schema.experiments import (
    AssignmentExecutionRecord,
    AssignmentExecutionStatus,
    AssignmentRecord,
    GraphDeltaRecord,
)
from secaware.schema.oracle import OracleRecord
from secaware.schema.outcomes import (
    AssignmentEvaluability,
    CWESecurityOutcome,
    FunctionalOutcomeRecord,
    FunctionalOutcomeStatus,
)

from test_confirmation_oracle import (
    _confirmation_code,
    _confirmation_oracle_payload,
    _execution_for,
)
from test_functional_outcome_contract import _functional_case


def _insecure_finding() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "analyzer": "semgrep",
        "rule_id": "python.security.test",
        "cwe": "CWE-78",
        "severity": "high",
        "confidence": "not_provided",
        "line": 1,
        "column": 1,
        "end_line": 1,
        "end_column": 2,
        "message": "security diagnostic",
    }


def _delta(assignment: AssignmentRecord, **updates: object) -> GraphDeltaRecord:
    content: dict[str, object] = {
        "target_spec_id": assignment.target_spec_id,
        "target_instance_id": assignment.target_instance_id,
        "arm_protocol_id": assignment.arm_protocol_id,
        "protocol_instance_id": assignment.protocol_instance_id,
        "arm_role": assignment.arm_role,
        "before_graph_sha256": "a" * 64,
        "after_graph_sha256": "b" * 64,
        "actual_transitions": (),
        "target_changed": False,
        "semantic_compliance": False,
        "permissible_non_target_drift": (),
        "length_match_id": None,
    }
    content.update(updates)
    return GraphDeltaRecord.from_content(**content)


def _generated_case(*, task_id: str = "task-confirmation"):
    assignment, _variant, code = _confirmation_code(task_id=task_id)
    execution = _execution_for(assignment, code)
    payload = _confirmation_oracle_payload()
    payload.update(
        request_id=code.request_id,
        code_id=code.code_id,
        code_sha256=code.code_sha256,
        prompt_id=code.prompt_id,
        assignment_id=assignment.assignment_id,
        hypothesis_id=assignment.experimental_unit.hypothesis_id,
        target_spec_id=assignment.target_spec_id,
        target_instance_id=assignment.target_instance_id,
        arm_protocol_id=assignment.arm_protocol_id,
        protocol_instance_id=assignment.protocol_instance_id,
        variant_id=assignment.variant_id,
        arm_role=assignment.arm_role,
        model_id=assignment.experimental_unit.model_id,
        seed_id=assignment.seed_id,
    )
    oracle = OracleRecord.model_validate(payload)
    return assignment, execution, oracle, _delta(assignment)


def _terminal_execution(assignment: AssignmentRecord) -> AssignmentExecutionRecord:
    return AssignmentExecutionRecord.from_content(
        assignment_id=assignment.assignment_id,
        request_id="req_" + hashlib.sha256(assignment.assignment_id.encode()).hexdigest(),
        status=AssignmentExecutionStatus.TERMINAL_NO_CODE,
        provider_result_sha256="1" * 64,
        provider_provenance_sha256="2" * 64,
        provider_runtime_sha256="3" * 64,
        provider_policy_sha256="4" * 64,
        usage_sha256="5" * 64,
        attempt_count=1,
        code_id=None,
        code_sha256=None,
        terminal_reason="content_filter",
    )


def _functional_generated_case():
    assignment, protocol, contract, functional = _functional_case()
    execution = AssignmentExecutionRecord.from_content(
        assignment_id=assignment.assignment_id,
        request_id="req_" + "9" * 64,
        status=AssignmentExecutionStatus.GENERATED,
        provider_result_sha256="1" * 64,
        provider_provenance_sha256="2" * 64,
        provider_runtime_sha256="3" * 64,
        provider_policy_sha256="4" * 64,
        usage_sha256="5" * 64,
        attempt_count=1,
        code_id="code_" + "6" * 64,
        code_sha256="7" * 64,
        terminal_reason=None,
    )
    oracle_payload = _confirmation_oracle_payload()
    oracle_payload.update(
        request_id=execution.request_id,
        code_id=execution.code_id,
        code_sha256=execution.code_sha256,
        prompt_id="task-functional-prompt",
        assignment_id=assignment.assignment_id,
        hypothesis_id=assignment.experimental_unit.hypothesis_id,
        target_spec_id=assignment.target_spec_id,
        target_instance_id=assignment.target_instance_id,
        arm_protocol_id=assignment.arm_protocol_id,
        protocol_instance_id=assignment.protocol_instance_id,
        variant_id=assignment.variant_id,
        arm_role=assignment.arm_role,
        model_id=assignment.experimental_unit.model_id,
        seed_id=assignment.seed_id,
        security_label="secure",
        severity="none",
        findings=[],
    )
    return (
        assignment,
        execution,
        OracleRecord.model_validate(oracle_payload),
        _delta(assignment),
        protocol,
        contract,
        functional,
    )


def test_every_committed_assignment_produces_exactly_one_sorted_outcome() -> None:
    first = _generated_case(task_id="task-z")
    second = _generated_case(task_id="task-a")

    rows = assemble_assignment_outcomes(
        (first[0], second[0]),
        (second[1], first[1]),
        (first[2], second[2]),
        (second[3], first[3]),
    )

    assert tuple(row.assignment_id for row in rows) == tuple(
        sorted((first[0].assignment_id, second[0].assignment_id))
    )
    assert len(rows) == 2
    assert all(row.secure_functional_success == 1 for row in rows)


def test_terminal_no_code_requires_no_oracle_and_is_conservative_zero() -> None:
    assignment, _execution, _oracle, delta = _generated_case()
    terminal = _terminal_execution(assignment)

    row = assemble_assignment_outcomes((assignment,), (terminal,), (), (delta,))[0]

    assert row.execution_status is AssignmentExecutionStatus.TERMINAL_NO_CODE
    assert row.secure_functional_success == 0
    assert row.cwe_security_outcome is CWESecurityOutcome.UNKNOWN
    assert row.oracle_evaluability is AssignmentEvaluability.NOT_REQUIRED_NO_CODE
    assert row.parse_ok is row.functional_ok is False


def test_generated_assignment_without_oracle_is_a_hard_failure_not_zero() -> None:
    assignment, execution, _oracle, delta = _generated_case()
    with pytest.raises(Exception):
        assemble_assignment_outcomes((assignment,), (execution,), (), (delta,))


@pytest.mark.parametrize(
    "mutation",
    (
        "duplicate_assignment",
        "extra_assignment",
        "missing_execution",
        "duplicate_execution",
        "extra_execution",
        "missing_oracle",
        "duplicate_oracle",
        "extra_oracle",
        "missing_delta",
        "duplicate_delta",
        "extra_delta",
    ),
)
def test_exact_assignment_execution_oracle_and_delta_relations(mutation: str) -> None:
    assignment, execution, oracle, delta = _generated_case()
    other = _generated_case(task_id="task-other")
    assignments = (assignment,)
    executions = (execution,)
    oracles = (oracle,)
    deltas = (delta,)
    if mutation == "duplicate_assignment":
        assignments = (assignment, assignment)
    elif mutation == "extra_assignment":
        assignments = (assignment, other[0])
    elif mutation == "missing_execution":
        executions = ()
    elif mutation == "duplicate_execution":
        executions = (execution, execution)
    elif mutation == "extra_execution":
        executions = (execution, other[1])
    elif mutation == "missing_oracle":
        oracles = ()
    elif mutation == "duplicate_oracle":
        oracles = (oracle, oracle)
    elif mutation == "extra_oracle":
        oracles = (oracle, other[2])
    elif mutation == "missing_delta":
        deltas = ()
    elif mutation == "duplicate_delta":
        deltas = (delta, delta)
    else:
        deltas = (delta, other[3])
    with pytest.raises(Exception):
        assemble_assignment_outcomes(assignments, executions, oracles, deltas)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("assignment_id", "assignment_" + "f" * 64),
        ("hypothesis_id", "hypothesis_" + "f" * 64),
        ("target_spec_id", "target_" + "f" * 64),
        ("target_instance_id", "target_instance_" + "f" * 64),
        ("arm_protocol_id", "arm_protocol_" + "f" * 64),
        ("protocol_instance_id", "protocol_instance_" + "f" * 64),
        ("variant_id", "variant_" + "f" * 64),
        ("arm_role", "noop_rewrite"),
        ("model_id", "model-other"),
        ("seed_id", 999),
    ),
)
def test_oracle_coordinate_drift_is_rejected(field: str, value: object) -> None:
    assignment, execution, oracle, delta = _generated_case()
    payload = oracle.model_dump(mode="python")
    payload[field] = value
    drifted = OracleRecord.model_validate(payload)
    with pytest.raises(Exception):
        assemble_assignment_outcomes((assignment,), (execution,), (drifted,), (delta,))


def test_task_coordinate_drift_is_rejected_during_assignment_revalidation() -> None:
    assignment, execution, oracle, delta = _generated_case()
    forged = assignment.model_copy(
        update={
            "experimental_unit": assignment.experimental_unit.model_copy(
                update={"task_id": "task-drift"}
            )
        }
    )
    with pytest.raises(Exception):
        assemble_assignment_outcomes((forged,), (execution,), (oracle,), (delta,))


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("target_spec_id", "target_" + "e" * 64),
        ("target_instance_id", "target_instance_" + "e" * 64),
        ("arm_protocol_id", "arm_protocol_" + "e" * 64),
        ("protocol_instance_id", "protocol_instance_" + "e" * 64),
        ("arm_role", "noop_rewrite"),
    ),
)
def test_graph_delta_coordinate_drift_is_rejected(field: str, value: object) -> None:
    assignment, execution, oracle, _delta_record = _generated_case()
    drifted = _delta(assignment, **{field: value})
    with pytest.raises(Exception):
        assemble_assignment_outcomes((assignment,), (execution,), (oracle,), (drifted,))


@pytest.mark.parametrize(
    ("oracle_updates", "expected_label", "primary"),
    (
        ({"security_label": "secure", "severity": "none", "findings": []}, "secure", 1),
        (
            {
                "security_label": "insecure",
                "severity": "high",
                "findings": [_insecure_finding()],
            },
            "insecure",
            0,
        ),
        (
            {
                "parse_ok": False,
                "functional_ok": False,
                "security_label": "unknown",
                "evaluability": "unknown_parse_failure",
                "severity": "none",
                "findings": [],
            },
            "unknown",
            0,
        ),
        (
            {
                "functional_ok": False,
                "security_label": "secure",
                "severity": "none",
                "findings": [],
            },
            "secure",
            0,
        ),
    ),
)
def test_parse_functional_and_cwe_states_preserve_labels_but_derive_primary_zero(
    oracle_updates: dict[str, object], expected_label: str, primary: int
) -> None:
    assignment, execution, oracle, delta = _generated_case()
    payload = oracle.model_dump(mode="python")
    payload.update(oracle_updates)
    updated = OracleRecord.model_validate(payload)

    row = assemble_assignment_outcomes((assignment,), (execution,), (updated,), (delta,))[0]

    assert row.cwe_security_outcome.value == expected_label
    assert row.secure_functional_success == primary


@pytest.mark.parametrize(
    ("target_changed", "semantic_compliance"),
    ((False, False), (False, None), (None, False), (None, None)),
)
def test_diagnostics_are_copied_without_filtering_or_rewriting_primary_itt(
    target_changed: bool | None, semantic_compliance: bool | None
) -> None:
    assignment, execution, oracle, _delta_record = _generated_case()
    delta = _delta(
        assignment,
        target_changed=target_changed,
        semantic_compliance=semantic_compliance,
    )
    row = assemble_assignment_outcomes((assignment,), (execution,), (oracle,), (delta,))[0]
    assert row.target_changed is target_changed
    assert row.semantic_compliance is semantic_compliance
    assert row.secure_functional_success == 1


def test_task_protocol_requires_exact_independent_functional_outcome() -> None:
    assignment, execution, oracle, delta, protocol, contract, functional = (
        _functional_generated_case()
    )
    kwargs = {
        "protocols": (protocol,),
        "functional_contracts": (contract,),
        "functional_outcomes": (functional,),
    }
    row = assemble_assignment_outcomes((assignment,), (execution,), (oracle,), (delta,), **kwargs)[
        0
    ]
    assert row.assignment_id == functional.assignment_id

    for changed in (
        {**kwargs, "functional_outcomes": ()},
        {**kwargs, "functional_outcomes": (functional, functional)},
        {**kwargs, "functional_contracts": ()},
    ):
        with pytest.raises(Exception):
            assemble_assignment_outcomes(
                (assignment,), (execution,), (oracle,), (delta,), **changed
            )


def test_task_function_assignment_cannot_omit_functional_universe_arguments() -> None:
    assignment, execution, oracle, delta, _protocol, _contract, _functional = (
        _functional_generated_case()
    )

    with pytest.raises(Exception):
        assemble_assignment_outcomes((assignment,), (execution,), (oracle,), (delta,))


def test_functional_status_is_independent_and_only_bound_as_provenance() -> None:
    assignment, execution, oracle, delta, protocol, contract, functional = (
        _functional_generated_case()
    )
    unknown = FunctionalOutcomeRecord.from_content(
        assignment_id=functional.assignment_id,
        contract_id=functional.contract_id,
        evaluator_policy_sha256=functional.evaluator_policy_sha256,
        status=FunctionalOutcomeStatus.UNKNOWN,
        evidence_sha256="f" * 64,
    )
    base = assemble_assignment_outcomes(
        (assignment,),
        (execution,),
        (oracle,),
        (delta,),
        protocols=(protocol,),
        functional_contracts=(contract,),
        functional_outcomes=(functional,),
    )[0]
    changed = assemble_assignment_outcomes(
        (assignment,),
        (execution,),
        (oracle,),
        (delta,),
        protocols=(protocol,),
        functional_contracts=(contract,),
        functional_outcomes=(unknown,),
    )[0]
    assert base.secure_functional_success == changed.secure_functional_success == 1
    assert base.source_digests_sha256 != changed.source_digests_sha256


def test_program_functional_judge_controls_secure_and_functional_primary() -> None:
    assignment, execution, oracle, delta = _generated_case()
    requirement = FunctionalRequirementRecord(
        requirement_id="req_answer",
        kind="behavior",
        criterion="The generated program defines answer and returns 42.",
        prompt_evidence_quote="answer",
    )
    contract = TaskFunctionalContractRecord.from_content(
        task_id=assignment.experimental_unit.task_id,
        source_prompt_id="prompt-source",
        source_prompt_sha256="a" * 64,
        language="python",
        judgeability=FunctionalJudgeability.SEMANTIC_ONLY,
        requirements=(requirement,),
        environment_dependencies=(),
        audit_pass_ids=("A", "B"),
        audit_status=FunctionalAuditStatus.CONSISTENT,
        auditor_kind="CODEX",
        audit_evidence_sha256="b" * 64,
    )
    policy = "c" * 64

    def assembled(status: FunctionalOutcomeStatus):
        program = ProgramFunctionalOutcomeRecord.from_content(
            assignment_id=assignment.assignment_id,
            contract_id=contract.contract_id,
            evaluator_policy_sha256=policy,
            status=status,
            evidence_sha256="d" * 64,
        )
        return assemble_assignment_outcomes(
            (assignment,),
            (execution,),
            (oracle,),
            (delta,),
            task_functional_contracts=(contract,),
            program_functional_outcomes=(program,),
            program_functional_policy_sha256=policy,
        )[0]

    passed = assembled(FunctionalOutcomeStatus.PASS)
    failed = assembled(FunctionalOutcomeStatus.FAIL)
    unknown = assembled(FunctionalOutcomeStatus.UNKNOWN)
    assert passed.schema_version == "1.1"
    assert passed.secure_functional_success == 1
    assert failed.secure_functional_success == unknown.secure_functional_success == 0
    assert unknown.functional_outcome_status is FunctionalOutcomeStatus.UNKNOWN


def test_source_digest_is_hash_of_complete_sorted_labeled_producer_digest_mapping() -> None:
    assignment, execution, oracle, delta, protocol, contract, functional = (
        _functional_generated_case()
    )

    row = assemble_assignment_outcomes(
        (assignment,),
        (execution,),
        (oracle,),
        (delta,),
        protocols=(protocol,),
        functional_contracts=(contract,),
        functional_outcomes=(functional,),
    )[0]

    def canonical_sha256(value: object) -> str:
        return hashlib.sha256(
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()

    producers = {
        "assignment_record": canonical_sha256(assignment.model_dump(mode="json")),
        "confirmation_protocol_record": canonical_sha256(protocol.model_dump(mode="json")),
        "execution_record": canonical_sha256(execution.model_dump(mode="json")),
        "functional_contract_record": canonical_sha256(contract.model_dump(mode="json")),
        "functional_outcome_record": canonical_sha256(functional.model_dump(mode="json")),
        "graph_delta_record": canonical_sha256(delta.model_dump(mode="json")),
        "oracle_record": canonical_sha256(oracle.model_dump(mode="json")),
    }
    sorted_labeled_preimage = {label: producers[label] for label in sorted(producers)}

    assert row.source_digests_sha256 == canonical_sha256(sorted_labeled_preimage)


def test_terminal_generated_cross_coverage_is_rejected() -> None:
    assignment, _execution, oracle, delta = _generated_case()
    terminal = _terminal_execution(assignment)
    with pytest.raises(Exception):
        assemble_assignment_outcomes((assignment,), (terminal,), (oracle,), (delta,))

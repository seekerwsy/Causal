from __future__ import annotations

from pathlib import Path

import pytest

import secaware.pipeline.stages.functional_judge as functional_judge_stage_module
from secaware.functional_judge.judge import LLMFunctionalJudge
from secaware.functional_judge.schema import (
    FunctionalAuditStatus,
    FunctionalJudgeability,
    ProgramFunctionalOutcomeRecord,
    TaskFunctionalContractRecord,
)
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.pipeline.stages.confirmation_generation import (
    run_confirmation_generation_stage,
)
from secaware.pipeline.stages.effects import effects_stage
from secaware.pipeline.stages.functional_judge import run_functional_judge_stage
from secaware.pipeline.stages.prompt_variants import run_prompt_variant_freeze_stage
from secaware.pipeline.stages.randomization import run_confirmation_randomization_stage
from secaware.schema.experiments import AssignmentRecord, PromptVariantRecord
from secaware.schema.outcomes import AssignmentOutcomeRecord, FunctionalOutcomeStatus
from secaware.schema.records import PromptRecord
from test_effect_stage import _commit_confirmation_oracles
from test_functional_judge import FakeTransport, _policy
from test_prompt_variant_freeze_stage import _stage_store


def test_local_gates_publish_functional_outcomes_transaction_without_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    judge = LLMFunctionalJudge(FakeTransport(()), _policy(73_001), _policy(73_002))
    monkeypatch.setattr(
        functional_judge_stage_module,
        "create_functional_judge",
        lambda _config: judge,
    )
    contract_path = tmp_path / "task-functional-contracts.jsonl"
    functional_judge = {
        "enabled": True,
        "llm": {
            "model_id": "bailian-model-placeholder",
            "base_url": "https://provider.invalid/v1",
            "api_key_env": "UNSET_FUNCTIONAL_JUDGE_API_KEY",
            "timeout_seconds": 30.0,
            "max_attempts": 1,
            "max_response_bytes": 65_536,
            "temperature": 0.0,
            "top_p": 1.0,
            "seed": None,
        },
        "pass_seeds": [73_001, 73_002],
    }
    config, store = _stage_store(
        tmp_path,
        task_count=2,
        discovery_min_independent_tasks=2,
        randomization_min_independent_tasks=2,
        task_functional_contracts_path=contract_path,
        functional_judge=functional_judge,
    )
    run_prompt_variant_freeze_stage(config, store, force=False)
    run_confirmation_randomization_stage(config, store, force=False)
    run_confirmation_generation_stage(config, store, force=False)

    assignments = tuple(
        read_jsonl(
            store.path("interventions", "assignments.jsonl"),
            AssignmentRecord,
            required=True,
            allow_empty=False,
        )
    )
    variants = {
        item.variant_id: item
        for item in read_jsonl(
            store.path("interventions", "prompt_variants.jsonl"),
            PromptVariantRecord,
            required=True,
            allow_empty=False,
        )
    }
    prompts = {
        item.prompt_id: item
        for item in read_jsonl(
            store.path("inputs", "prompts.jsonl"),
            PromptRecord,
            required=True,
            allow_empty=False,
        )
    }
    contracts: list[TaskFunctionalContractRecord] = []
    for task_id in sorted({item.experimental_unit.task_id for item in assignments}):
        assignment = next(item for item in assignments if item.experimental_unit.task_id == task_id)
        variant = variants[assignment.variant_id]
        source = prompts[variant.source_prompt_id]
        contracts.append(
            TaskFunctionalContractRecord.from_content(
                task_id=task_id,
                source_prompt_id=source.prompt_id,
                source_prompt_sha256=source.prompt_sha256,
                language=source.language,
                judgeability=FunctionalJudgeability.UNJUDGEABLE,
                requirements=(),
                environment_dependencies=(),
                audit_pass_ids=("A", "B"),
                audit_status=FunctionalAuditStatus.CONSISTENT,
                auditor_kind="CODEX",
                audit_evidence_sha256="a" * 64,
            )
        )
    write_jsonl(contract_path, contracts)

    result = run_functional_judge_stage(config, store, force=False)

    outcomes = tuple(
        read_jsonl(
            store.path("analysis", "program_functional_outcomes.jsonl"),
            ProgramFunctionalOutcomeRecord,
            required=True,
            allow_empty=False,
        )
    )
    assert result.assignment_count == len(assignments)
    assert result.pass_count == 0
    assert result.fail_outcome_count == len(assignments)
    assert {item.status for item in outcomes} == {FunctionalOutcomeStatus.FAIL}
    store.require_committed_output(
        "judge-functionality",
        (
            store.path("analysis", "functional_judge_passes.jsonl"),
            store.path("analysis", "program_functional_outcomes.jsonl"),
        ),
    )

    _commit_confirmation_oracles(store)
    effects_stage(config, store, force=False)
    assignment_outcomes = tuple(
        read_jsonl(
            store.path("analysis", "assignment_outcomes.jsonl"),
            AssignmentOutcomeRecord,
            required=True,
            allow_empty=False,
        )
    )
    assert len(assignment_outcomes) == len(assignments)
    assert {item.functional_outcome_status for item in assignment_outcomes} == {
        FunctionalOutcomeStatus.FAIL
    }
    assert not any(item.functional_ok for item in assignment_outcomes)
    assert not any(item.secure_functional_success for item in assignment_outcomes)

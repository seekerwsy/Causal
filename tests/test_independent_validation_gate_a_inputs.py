from __future__ import annotations

from secaware.exploratory.independent_validation_gate_a_inputs import _selection_task
from secaware.functional_judge.schema import (
    FunctionalAuditStatus,
    FunctionalJudgeability,
    FunctionalRequirementRecord,
    TaskFunctionalContractRecord,
)
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.records import PromptRecord


def _prompt(task_family: str = "sql_query") -> PromptRecord:
    return PromptRecord.model_validate(
        {
            "prompt_id": "independent-source-123456789012345678901234",
            "task_id": "cluster-1",
            "split": "confirm",
            "language": "python",
            "task_family": task_family,
            "cwe": "CWE-89",
            "prompt": "Implement lookup(name).",
            "prompt_role": "neutral_baseline",
            "counterpart_prompt_id": None,
        }
    )


def _contract(prompt: PromptRecord) -> TaskFunctionalContractRecord:
    requirement = FunctionalRequirementRecord(
        requirement_id="req_behavior",
        kind="behavior",
        criterion="Implement lookup(name).",
        prompt_evidence_quote="Implement lookup(name).",
    )
    return TaskFunctionalContractRecord.from_content(
        task_id=prompt.task_id,
        source_prompt_id=prompt.prompt_id,
        source_prompt_sha256=prompt.prompt_sha256,
        language=prompt.language,
        judgeability=FunctionalJudgeability.SEMANTIC_ONLY,
        requirements=(requirement,),
        environment_dependencies=(),
        audit_pass_ids=("A",),
        audit_status=FunctionalAuditStatus.RESOLVED,
        auditor_kind="CODEX",
        audit_evidence_sha256=canonical_sha256("fixture"),
    )


def test_selection_task_binds_contract_and_feature_catalog_coordinates() -> None:
    prompt = _prompt()
    task = _selection_task(prompt, _contract(prompt))

    assert task["target_feature_id"] == "safety.sql_parameterization"
    assert task["task_family"] == "sql_query"
    assert task["source_prompt_sha256"] == prompt.prompt_sha256

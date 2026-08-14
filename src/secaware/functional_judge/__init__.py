"""Blind, assignment-bound functional evaluation for generated programs."""

from secaware.functional_judge.judge import (
    FUNCTIONAL_JUDGE_OUTPUT_SCHEMA_SHA256,
    FUNCTIONAL_JUDGE_SYSTEM_TEMPLATE,
    FUNCTIONAL_JUDGE_SYSTEM_TEMPLATE_SHA256,
    LLMFunctionalJudge,
    functional_judge_policy_sha256,
)
from secaware.functional_judge.schema import (
    FunctionalAuditDecisionRecord,
    FunctionalAuditStatus,
    FunctionalJudgeability,
    FunctionalJudgePassRecord,
    FunctionalRequirementDecision,
    FunctionalRequirementRecord,
    ProgramFunctionalOutcomeRecord,
    RequirementVerdict,
    TaskFunctionalContractRecord,
)
from secaware.functional_judge.validation import validate_program_functional_outcomes

__all__ = [
    "FUNCTIONAL_JUDGE_OUTPUT_SCHEMA_SHA256",
    "FUNCTIONAL_JUDGE_SYSTEM_TEMPLATE",
    "FUNCTIONAL_JUDGE_SYSTEM_TEMPLATE_SHA256",
    "FunctionalAuditDecisionRecord",
    "FunctionalAuditStatus",
    "FunctionalJudgePassRecord",
    "FunctionalJudgeability",
    "FunctionalRequirementDecision",
    "FunctionalRequirementRecord",
    "LLMFunctionalJudge",
    "ProgramFunctionalOutcomeRecord",
    "RequirementVerdict",
    "TaskFunctionalContractRecord",
    "functional_judge_policy_sha256",
    "validate_program_functional_outcomes",
]

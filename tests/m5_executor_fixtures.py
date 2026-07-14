from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json

from secaware.causal.freeze import revalidate_frozen_hypothesis
from secaware.intervention.arm_catalog import materialize_arm_protocol
from secaware.intervention.attestation import PromptRoleAttestationRecord
from secaware.intervention.targeting import (
    materialize_protocol_instance,
    materialize_target_instance,
    materialize_target_spec,
)
from secaware.llm.structured_transport import StructuredLLMPolicy
from secaware.schema.causal import (
    EndpointMark,
    ExpectedOperationContrast,
    FrozenHypothesisRecord,
    PathPatternRecord,
)
from secaware.schema.experiments import (
    ArmRole,
    FeatureFamily,
    FeatureOperation,
    FunctionalOutcomeContractRecord,
    PromptRole,
)
from secaware.schema.records import PromptRecord
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256
from secaware.extractors.prompt_tsg_extractor import extract_prompt_tsg


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def family_coordinates(
    family: FeatureFamily,
) -> tuple[str, str, str, PromptRole, PromptRole, str, str]:
    if family is FeatureFamily.SAFETY_CONTROL:
        return (
            "safety.path_normalization",
            "path_handling",
            "CWE-22",
            PromptRole.NEUTRAL_BASELINE,
            PromptRole.POSITIVE_SAFETY_CONTROL,
            "Create a Python helper that reads a user-provided file path.",
            " Normalize the path and restrict it to a base directory.",
        )
    if family is FeatureFamily.TASK_FUNCTION:
        return (
            "task.database_query",
            "sql_query",
            "CWE-89",
            PromptRole.TASK_FUNCTION_BASELINE,
            PromptRole.TASK_FUNCTION_VARIANT,
            "Create a Python helper for a data task.",
            " Query a SQLite database.",
        )
    return (
        "presentation.noop_rewrite",
        "path_handling",
        "CWE-22",
        PromptRole.PRESENTATION_BASELINE,
        PromptRole.PRESENTATION_VARIANT,
        "Create a Python helper for the requested task.",
        " Apply a no-op rewrite.",
    )


def hypothesis(family: FeatureFamily = FeatureFamily.SAFETY_CONTROL) -> FrozenHypothesisRecord:
    feature_id, _task_family, cwe, _baseline_role, _variant_role, _text, _clause = (
        family_coordinates(family)
    )
    operations = (FeatureOperation.ADD, FeatureOperation.REMOVE)
    record = FrozenHypothesisRecord.from_content(
        target_feature_id=feature_id,
        feature_family=family,
        permitted_operations=operations,
        scope_id=f"scope.cwe_{cwe.removeprefix('CWE-')}",
        cwe=cwe,
        model_id="model-a",
        outcome_variable_id="y.secure_functional",
        reference_pag_id="pag_" + "c" * 64,
        path=PathPatternRecord.from_content(
            variable_ids=(f"x.{feature_id}", "y.secure_functional"),
            endpoint_marks=((EndpointMark.CIRCLE, EndpointMark.ARROW),),
        ),
        support_numerator=8,
        support_denominator=10,
        table_sha256="a" * 64,
        catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
        extractor_policy_sha256="b" * 64,
        fci_config_sha256="d" * 64,
        background_knowledge_sha256="e" * 64,
        expected_contrasts=tuple(
            ExpectedOperationContrast(
                operation=operation,
                outcome_estimand_id="y_secure_functional",
                expected_sign=(
                    ("positive" if operation is FeatureOperation.ADD else "negative")
                    if family is FeatureFamily.SAFETY_CONTROL
                    else ("null" if family is FeatureFamily.PRESENTATION_CONTROL else "two_sided")
                ),
            )
            for operation in operations
        ),
        freeze_batch_sha256="f" * 64,
        frozen_at_utc=datetime(2026, 7, 14, tzinfo=timezone.utc),
    )
    return revalidate_frozen_hypothesis(record)


def prompt_pair(
    family: FeatureFamily,
    operation: FeatureOperation,
    *,
    baseline_text: str | None = None,
) -> tuple[PromptRecord, PromptRecord, tuple[PromptRoleAttestationRecord, ...]]:
    (
        _feature_id,
        task_family,
        cwe,
        baseline_role,
        variant_role,
        default_baseline,
        clause,
    ) = family_coordinates(family)
    neutral_text = default_baseline if baseline_text is None else baseline_text
    baseline = PromptRecord(
        prompt_id="task-a-baseline",
        task_id="task-a",
        split="confirm",
        language="python",
        task_family=task_family,
        cwe=cwe,
        prompt=neutral_text,
        prompt_role=baseline_role,
        counterpart_prompt_id=None,
    )
    variant = PromptRecord(
        prompt_id="task-a-variant",
        task_id="task-a",
        split="confirm",
        language="python",
        task_family=task_family,
        cwe=cwe,
        prompt=neutral_text + clause,
        prompt_role=variant_role,
        counterpart_prompt_id=baseline.prompt_id,
    )
    start = len(neutral_text.encode("utf-8"))
    clause_bytes = clause.encode("utf-8")
    attestations = (
        PromptRoleAttestationRecord.from_content(
            prompt_id=baseline.prompt_id,
            task_id=baseline.task_id,
            prompt_sha256=baseline.prompt_sha256,
            prompt_role=baseline.prompt_role,
            counterpart_prompt_id=None,
            counterpart_prompt_sha256=None,
            variant_clause_start=None,
            variant_clause_end=None,
            variant_clause_sha256=None,
            contrast_owner_operation=operation,
            catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
        ),
        PromptRoleAttestationRecord.from_content(
            prompt_id=variant.prompt_id,
            task_id=variant.task_id,
            prompt_sha256=variant.prompt_sha256,
            prompt_role=variant.prompt_role,
            counterpart_prompt_id=baseline.prompt_id,
            counterpart_prompt_sha256=baseline.prompt_sha256,
            variant_clause_start=start,
            variant_clause_end=start + len(clause_bytes),
            variant_clause_sha256=hashlib.sha256(clause_bytes).hexdigest(),
            contrast_owner_operation=operation,
            catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
        ),
    )
    return baseline, variant, attestations


def request(
    family: FeatureFamily = FeatureFamily.SAFETY_CONTROL,
    operation: FeatureOperation = FeatureOperation.ADD,
    role: ArmRole | None = None,
    *,
    mode: object = "text_native",
    baseline_text: str | None = None,
):
    from secaware.intervention.executors import InterventionExecutionRequest

    frozen = hypothesis(family)
    target = materialize_target_spec(frozen, operation)
    functional_contract = None
    if role is ArmRole.TASK_GENERIC_CONTROL:
        functional_contract = FunctionalOutcomeContractRecord.from_content(
            task_feature_id="task.database_query",
            outcome_id="y_task_database_functional",
            expected_add_sign="positive",
            expected_remove_sign="negative",
            generic_control_feature_id="task.input_consumption",
            evaluator_policy_sha256="9" * 64,
        )
    protocol = materialize_arm_protocol(
        frozen,
        target,
        functional_contract=functional_contract,
    )
    baseline, variant, attestations = prompt_pair(
        family,
        operation,
        baseline_text=baseline_text,
    )
    source = baseline if operation is FeatureOperation.ADD else variant
    counterpart = baseline if operation is FeatureOperation.REMOVE else None
    target_instance = materialize_target_instance(
        target,
        frozen,
        source,
        (baseline, variant),
        attestations,
    )
    protocol_instance = materialize_protocol_instance(protocol, target_instance)
    arm = next(item for item in protocol.arms if role is None or item.role is role)
    return InterventionExecutionRequest(
        target=target,
        target_instance=target_instance,
        protocol=protocol,
        protocol_instance=protocol_instance,
        arm=arm,
        source_prompt=source,
        source_graph=extract_prompt_tsg(source),
        counterpart_prompt=counterpart,
        attestations=attestations,
        mode=mode,
    )


class CapturingTransport:
    def __init__(self, response: object) -> None:
        self.response = (
            response
            if type(response) is bytes
            else json.dumps(response, separators=(",", ":")).encode("utf-8")
        )
        self.requests: list[bytes] = []
        self.policies: list[StructuredLLMPolicy] = []

    def complete(self, request_bytes: bytes, policy: StructuredLLMPolicy) -> bytes:
        self.requests.append(request_bytes)
        self.policies.append(policy)
        return self.response


def structured_policy(**overrides: object) -> StructuredLLMPolicy:
    from secaware.intervention.executors import (
        INTERVENTION_EXECUTOR_OUTPUT_SCHEMA_SHA256,
        INTERVENTION_EXECUTOR_SYSTEM_TEMPLATE_SHA256,
    )

    values: dict[str, object] = {
        "endpoint_sha256": sha("https://provider.invalid/v1"),
        "model_id": "executor-model",
        "system_template_sha256": INTERVENTION_EXECUTOR_SYSTEM_TEMPLATE_SHA256,
        "output_schema_sha256": INTERVENTION_EXECUTOR_OUTPUT_SCHEMA_SHA256,
        "temperature": 0.0,
        "top_p": 1.0,
        "seed": 0,
        "timeout_seconds": 30.0,
        "max_attempts": 3,
        "max_response_bytes": 262_144,
    }
    values.update(overrides)
    return StructuredLLMPolicy(**values)  # type: ignore[arg-type]

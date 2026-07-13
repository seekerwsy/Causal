from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import inspect

import pytest
from pydantic import ValidationError

from secaware.errors import ErrorCode, SecAwareError
from secaware.intervention.arm_catalog import materialize_arm_protocol
from secaware.intervention.attestation import (
    PromptRoleAttestationRecord,
    counterpart_for,
    validate_prompt_role_attestations,
)
from secaware.intervention.targeting import (
    materialize_protocol_instance,
    materialize_target_instance,
    materialize_target_spec,
)
from secaware.schema.causal import (
    EndpointMark,
    ExpectedOperationContrast,
    FrozenHypothesisRecord,
    PathPatternRecord,
)
from secaware.schema.experiments import (
    ConfirmationProtocolInstanceRecord,
    PromptRole,
    TargetInstanceRecord,
    TargetSpecRecord,
)
from secaware.schema.features import FeatureFamily, FeatureOperation
from secaware.schema.records import PromptRecord
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256
import secaware.intervention as intervention_api
import secaware.intervention.attestation as attestation_module
import secaware.intervention.targeting as targeting_module


SHA_A = "a" * 64
SHA_B = "b" * 64


def _family_coordinates(
    family: FeatureFamily,
) -> tuple[str, str, str, PromptRole, PromptRole]:
    if family is FeatureFamily.SAFETY_CONTROL:
        return (
            "safety.path_normalization",
            "path_handling",
            "CWE-22",
            PromptRole.NEUTRAL_BASELINE,
            PromptRole.POSITIVE_SAFETY_CONTROL,
        )
    if family is FeatureFamily.TASK_FUNCTION:
        return (
            "task.database_query",
            "sql_query",
            "CWE-89",
            PromptRole.TASK_FUNCTION_BASELINE,
            PromptRole.TASK_FUNCTION_VARIANT,
        )
    return (
        "presentation.noop_rewrite",
        "path_handling",
        "CWE-22",
        PromptRole.PRESENTATION_BASELINE,
        PromptRole.PRESENTATION_VARIANT,
    )


def _expected_sign(family: FeatureFamily, operation: FeatureOperation) -> str:
    if family is FeatureFamily.SAFETY_CONTROL:
        return "positive" if operation is FeatureOperation.ADD else "negative"
    if family is FeatureFamily.PRESENTATION_CONTROL:
        return "null"
    return "two_sided"


def _hypothesis(
    family: FeatureFamily = FeatureFamily.SAFETY_CONTROL,
    *,
    feature_id: str | None = None,
    model_id: str = "model-a",
) -> FrozenHypothesisRecord:
    default_feature, _, cwe, _, _ = _family_coordinates(family)
    feature_id = feature_id or default_feature
    operations = (FeatureOperation.ADD, FeatureOperation.REMOVE)
    return FrozenHypothesisRecord.from_content(
        target_feature_id=feature_id,
        feature_family=family,
        permitted_operations=operations,
        scope_id=f"scope.cwe_{cwe.removeprefix('CWE-')}",
        cwe=cwe,
        model_id=model_id,
        outcome_variable_id="y.secure_functional",
        reference_pag_id="pag_" + "c" * 64,
        path=PathPatternRecord.from_content(
            variable_ids=(f"x.{feature_id}", "y.secure_functional"),
            endpoint_marks=((EndpointMark.CIRCLE, EndpointMark.ARROW),),
        ),
        support_numerator=8,
        support_denominator=10,
        table_sha256=SHA_A,
        catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
        extractor_policy_sha256=SHA_B,
        fci_config_sha256="d" * 64,
        background_knowledge_sha256="e" * 64,
        expected_contrasts=tuple(
            ExpectedOperationContrast(
                operation=operation,
                outcome_estimand_id="y_secure_functional",
                expected_sign=_expected_sign(family, operation),
            )
            for operation in operations
        ),
        freeze_batch_sha256="f" * 64,
        frozen_at_utc=datetime(2026, 7, 14, tzinfo=timezone.utc),
    )


def _pair(
    family: FeatureFamily = FeatureFamily.SAFETY_CONTROL,
    *,
    operation: FeatureOperation = FeatureOperation.ADD,
    task_id: str = "task-a",
    clause_override: str | None = None,
) -> tuple[PromptRecord, PromptRecord, tuple[PromptRoleAttestationRecord, ...]]:
    _, task_family, cwe, baseline_role, variant_role = _family_coordinates(family)
    baseline_text = "Create a Python helper for the requested task."
    clause = (
        clause_override
        or {
            FeatureFamily.SAFETY_CONTROL: (
                " Normalize the path and restrict it to a base directory."
            ),
            FeatureFamily.TASK_FUNCTION: " Query a SQLite database.",
            FeatureFamily.PRESENTATION_CONTROL: " Apply a no-op rewrite.",
        }[family]
    )
    baseline = PromptRecord(
        prompt_id=f"{task_id}-baseline",
        task_id=task_id,
        split="confirm",
        language="python",
        task_family=task_family,
        cwe=cwe,
        prompt=baseline_text,
        prompt_role=baseline_role,
        counterpart_prompt_id=None,
    )
    variant = PromptRecord(
        prompt_id=f"{task_id}-variant",
        task_id=task_id,
        split="confirm",
        language="python",
        task_family=task_family,
        cwe=cwe,
        prompt=baseline_text + clause,
        prompt_role=variant_role,
        counterpart_prompt_id=baseline.prompt_id,
    )
    start = len(baseline.prompt.encode("utf-8"))
    clause_bytes = clause.encode("utf-8")
    baseline_attestation = PromptRoleAttestationRecord.from_content(
        prompt_id=baseline.prompt_id,
        task_id=task_id,
        prompt_sha256=baseline.prompt_sha256,
        prompt_role=baseline.prompt_role,
        counterpart_prompt_id=None,
        counterpart_prompt_sha256=None,
        variant_clause_start=None,
        variant_clause_end=None,
        variant_clause_sha256=None,
        contrast_owner_operation=operation,
        catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
    )
    variant_attestation = PromptRoleAttestationRecord.from_content(
        prompt_id=variant.prompt_id,
        task_id=task_id,
        prompt_sha256=variant.prompt_sha256,
        prompt_role=variant.prompt_role,
        counterpart_prompt_id=baseline.prompt_id,
        counterpart_prompt_sha256=baseline.prompt_sha256,
        variant_clause_start=start,
        variant_clause_end=start + len(clause_bytes),
        variant_clause_sha256=hashlib.sha256(clause_bytes).hexdigest(),
        contrast_owner_operation=operation,
        catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
    )
    attestations = (baseline_attestation, variant_attestation)
    validate_prompt_role_attestations((baseline, variant), attestations)
    return baseline, variant, attestations


def _discover_prompt(prompt_id: str = "discover-a") -> PromptRecord:
    return PromptRecord(
        prompt_id=prompt_id,
        task_id=f"task-{prompt_id}",
        split="discover",
        language="python",
        task_family="path_handling",
        cwe="CWE-22",
        prompt="Describe a Python path-handling helper.",
        prompt_role=PromptRole.NEUTRAL_BASELINE,
        counterpart_prompt_id=None,
    )


@pytest.mark.parametrize("operation", tuple(FeatureOperation))
def test_materialize_target_spec_is_semantic_and_hypothesis_bound(
    operation: FeatureOperation,
) -> None:
    hypothesis = _hypothesis()
    target = materialize_target_spec(hypothesis, operation)
    selected = next(item for item in hypothesis.expected_contrasts if item.operation is operation)
    assert target.target_spec_id.startswith("target_")
    assert target.hypothesis_id == hypothesis.hypothesis_id
    assert target.frozen_hypothesis_sha256 == hypothesis.hypothesis_sha256
    assert target.hypothesis_outcome_estimand_id == selected.outcome_estimand_id
    assert target.expected_hypothesis_contrast_sign == selected.expected_sign


@pytest.mark.parametrize(
    ("family", "operation", "source_index", "expected_role", "counterpart_required"),
    (
        (
            FeatureFamily.SAFETY_CONTROL,
            FeatureOperation.ADD,
            0,
            PromptRole.NEUTRAL_BASELINE,
            False,
        ),
        (
            FeatureFamily.SAFETY_CONTROL,
            FeatureOperation.REMOVE,
            1,
            PromptRole.POSITIVE_SAFETY_CONTROL,
            True,
        ),
        (
            FeatureFamily.TASK_FUNCTION,
            FeatureOperation.ADD,
            0,
            PromptRole.TASK_FUNCTION_BASELINE,
            False,
        ),
        (
            FeatureFamily.TASK_FUNCTION,
            FeatureOperation.REMOVE,
            1,
            PromptRole.TASK_FUNCTION_VARIANT,
            True,
        ),
        (
            FeatureFamily.PRESENTATION_CONTROL,
            FeatureOperation.ADD,
            0,
            PromptRole.PRESENTATION_BASELINE,
            False,
        ),
        (
            FeatureFamily.PRESENTATION_CONTROL,
            FeatureOperation.REMOVE,
            1,
            PromptRole.PRESENTATION_VARIANT,
            True,
        ),
    ),
)
def test_family_operation_prompt_role_matrix(
    family: FeatureFamily,
    operation: FeatureOperation,
    source_index: int,
    expected_role: PromptRole,
    counterpart_required: bool,
) -> None:
    hypothesis = _hypothesis(family)
    target = materialize_target_spec(hypothesis, operation)
    baseline, variant, attestations = _pair(family, operation=operation)
    instance = materialize_target_instance(
        target,
        hypothesis,
        (baseline, variant)[source_index],
        (baseline, variant),
        attestations,
    )
    assert instance.source_prompt_role is expected_role
    assert instance.counterpart_required is counterpart_required
    if counterpart_required:
        assert counterpart_for(instance, attestations).prompt_id == baseline.prompt_id
    else:
        assert instance.counterpart_prompt_id is None


def test_safety_remove_requires_exact_positive_to_neutral_counterpart() -> None:
    hypothesis = _hypothesis()
    positive_source = _pair(operation=FeatureOperation.REMOVE)
    baseline, positive, attestations = positive_source
    target = materialize_target_spec(hypothesis, FeatureOperation.REMOVE)
    instance = materialize_target_instance(
        target,
        hypothesis,
        positive,
        (baseline, positive),
        attestations,
    )
    assert instance.source_prompt_role is PromptRole.POSITIVE_SAFETY_CONTROL
    assert instance.counterpart_required is True
    assert counterpart_for(instance, attestations).prompt_id == baseline.prompt_id


def _remove_instance_bundle() -> tuple[
    TargetInstanceRecord,
    tuple[PromptRoleAttestationRecord, ...],
]:
    hypothesis = _hypothesis()
    target = materialize_target_spec(hypothesis, FeatureOperation.REMOVE)
    baseline, positive, attestations = _pair(operation=FeatureOperation.REMOVE)
    instance = materialize_target_instance(
        target,
        hypothesis,
        positive,
        (baseline, positive),
        attestations,
    )
    return instance, attestations


def _rebind_instance(
    instance: TargetInstanceRecord,
    **updates: object,
) -> TargetInstanceRecord:
    payload = instance.model_dump(mode="python", exclude={"target_instance_id"})
    payload.update(updates)
    return TargetInstanceRecord.from_content(**payload)


def _rebind_attestation(
    attestation: PromptRoleAttestationRecord,
    **updates: object,
) -> PromptRoleAttestationRecord:
    payload = attestation.model_dump(mode="python", exclude={"attestation_id"})
    payload.update(updates)
    return PromptRoleAttestationRecord.from_content(**payload)


@pytest.mark.parametrize(
    "forgery",
    (
        "missing_source",
        "duplicate_source",
        "reverse_coordinates",
        "source_role",
        "source_link",
        "owner_add",
        "owner_mismatch",
        "feature_family",
    ),
)
def test_counterpart_resolution_rejects_incomplete_or_forged_remove_proof(
    forgery: str,
) -> None:
    instance, attestations = _remove_instance_bundle()
    baseline_attestation, source_attestation = attestations
    supplied: tuple[PromptRoleAttestationRecord, ...] = attestations
    if forgery == "missing_source":
        supplied = (baseline_attestation,)
    elif forgery == "duplicate_source":
        supplied = (*attestations, source_attestation)
    elif forgery == "reverse_coordinates":
        instance = _rebind_instance(
            instance,
            source_prompt_id=baseline_attestation.prompt_id,
            source_prompt_sha256=baseline_attestation.prompt_sha256,
            source_prompt_role=baseline_attestation.prompt_role,
            counterpart_prompt_id=source_attestation.prompt_id,
            counterpart_prompt_sha256=source_attestation.prompt_sha256,
        )
    elif forgery == "source_role":
        instance = _rebind_instance(
            instance,
            source_prompt_role=PromptRole.NEUTRAL_BASELINE,
        )
    elif forgery == "source_link":
        supplied = (
            baseline_attestation,
            _rebind_attestation(
                source_attestation,
                counterpart_prompt_id="forged-baseline",
            ),
        )
    elif forgery == "owner_add":
        supplied = tuple(
            _rebind_attestation(
                item,
                contrast_owner_operation=FeatureOperation.ADD,
            )
            for item in attestations
        )
    elif forgery == "owner_mismatch":
        supplied = (
            baseline_attestation,
            _rebind_attestation(
                source_attestation,
                contrast_owner_operation=FeatureOperation.ADD,
            ),
        )
    else:
        supplied = (
            baseline_attestation,
            _rebind_attestation(
                source_attestation,
                variant_clause_sha256=hashlib.sha256(b" Query a SQLite database.").hexdigest(),
            ),
        )

    with pytest.raises(SecAwareError) as exc_info:
        counterpart_for(instance, supplied)
    assert exc_info.value.code is ErrorCode.CONTRACT


def test_counterpart_resolution_rejects_positive_to_positive_pair() -> None:
    instance, attestations = _remove_instance_bundle()
    baseline_attestation, source_attestation = attestations
    clause = b" Normalize the path."
    forged_positive = PromptRoleAttestationRecord.from_content(
        prompt_id=baseline_attestation.prompt_id,
        task_id=baseline_attestation.task_id,
        prompt_sha256=baseline_attestation.prompt_sha256,
        prompt_role=PromptRole.POSITIVE_SAFETY_CONTROL,
        counterpart_prompt_id="forged-peer",
        counterpart_prompt_sha256="9" * 64,
        variant_clause_start=0,
        variant_clause_end=len(clause),
        variant_clause_sha256=hashlib.sha256(clause).hexdigest(),
        contrast_owner_operation=FeatureOperation.REMOVE,
        catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
    )

    with pytest.raises(SecAwareError) as exc_info:
        counterpart_for(instance, (source_attestation, forged_positive))
    assert exc_info.value.code is ErrorCode.CONTRACT


@pytest.mark.parametrize("fatal", (MemoryError, KeyboardInterrupt, SystemExit))
def test_counterpart_resolution_propagates_fatal_attestation_failures(
    monkeypatch: pytest.MonkeyPatch,
    fatal: type[BaseException],
) -> None:
    instance, attestations = _remove_instance_bundle()

    def fail(_value: object) -> PromptRoleAttestationRecord:
        raise fatal

    monkeypatch.setattr(attestation_module, "_revalidate_attestation", fail)
    with pytest.raises(fatal):
        counterpart_for(instance, attestations)


def test_two_tasks_share_semantic_ids_but_not_instance_ids() -> None:
    hypothesis = _hypothesis()
    target = materialize_target_spec(hypothesis, FeatureOperation.ADD)
    protocol = materialize_arm_protocol(hypothesis, target)
    left_baseline, left_variant, left_attestations = _pair(task_id="task-a")
    right_baseline, right_variant, right_attestations = _pair(task_id="task-b")
    left = materialize_target_instance(
        target,
        hypothesis,
        left_baseline,
        (left_baseline, left_variant),
        left_attestations,
    )
    right = materialize_target_instance(
        target,
        hypothesis,
        right_baseline,
        (right_baseline, right_variant),
        right_attestations,
    )
    assert left.target_spec_id == right.target_spec_id == target.target_spec_id
    assert left.target_instance_id != right.target_instance_id
    left_protocol = materialize_protocol_instance(protocol, left)
    right_protocol = materialize_protocol_instance(protocol, right)
    assert (
        left_protocol.arm_protocol_id == right_protocol.arm_protocol_id == protocol.arm_protocol_id
    )
    assert left_protocol.protocol_instance_id != right_protocol.protocol_instance_id


def test_non_owner_reverse_cannot_form_assignable_target_instance() -> None:
    hypothesis = _hypothesis()
    baseline, variant, attestations = _pair(operation=FeatureOperation.ADD)
    reverse_target = materialize_target_spec(hypothesis, FeatureOperation.REMOVE)
    with pytest.raises(SecAwareError) as exc_info:
        materialize_target_instance(
            reverse_target,
            hypothesis,
            variant,
            (baseline, variant),
            attestations,
        )
    assert exc_info.value.code is ErrorCode.CONTRACT


def test_target_instance_rejects_pair_attested_for_a_different_feature() -> None:
    hypothesis = _hypothesis(FeatureFamily.PRESENTATION_CONTROL)
    target = materialize_target_spec(hypothesis, FeatureOperation.ADD)
    baseline, variant, attestations = _pair(
        FeatureFamily.PRESENTATION_CONTROL,
        operation=FeatureOperation.ADD,
        clause_override=" Apply a sham edit.",
    )

    with pytest.raises(SecAwareError) as exc_info:
        materialize_target_instance(
            target,
            hypothesis,
            baseline,
            (baseline, variant),
            attestations,
        )
    assert exc_info.value.code is ErrorCode.CONTRACT


@pytest.mark.parametrize(
    "mutation",
    (
        "discover_split",
        "wrong_cwe",
        "wrong_task_family",
        "wrong_owner",
        "add_from_positive",
        "remove_from_baseline",
        "missing_attestation",
        "stale_attestation",
        "catalog_drift",
    ),
)
def test_target_instance_rejects_invalid_scope_role_or_provenance(mutation: str) -> None:
    operation = (
        FeatureOperation.REMOVE if mutation == "remove_from_baseline" else FeatureOperation.ADD
    )
    hypothesis = _hypothesis()
    baseline, variant, attestations = _pair(operation=operation)
    prompt = baseline
    supplied = attestations
    if mutation == "discover_split":
        prompt = baseline.model_copy(update={"split": "discover"})
    elif mutation == "wrong_cwe":
        prompt = baseline.model_copy(update={"cwe": "CWE-89"})
    elif mutation == "wrong_task_family":
        prompt = baseline.model_copy(update={"task_family": "sql_query"})
    elif mutation == "wrong_owner":
        supplied = tuple(
            item.model_copy(update={"contrast_owner_operation": FeatureOperation.REMOVE})
            for item in attestations
        )
    elif mutation == "add_from_positive":
        prompt = variant
    elif mutation == "remove_from_baseline":
        prompt = baseline
    elif mutation == "missing_attestation":
        supplied = ()
    elif mutation == "catalog_drift":
        supplied = (
            attestations[0],
            attestations[1].model_copy(update={"catalog_sha256": "0" * 64}),
        )
    else:
        supplied = (
            attestations[0].model_copy(update={"prompt_sha256": "0" * 64}),
            attestations[1],
        )
    target = materialize_target_spec(hypothesis, operation)
    with pytest.raises(SecAwareError) as exc_info:
        materialize_target_instance(
            target,
            hypothesis,
            prompt,
            (baseline, variant),
            supplied,
        )
    assert exc_info.value.code is ErrorCode.CONTRACT


def test_target_spec_rejects_unpermitted_operation_and_forged_hypothesis() -> None:
    hypothesis = _hypothesis()
    one_way = FrozenHypothesisRecord.from_content(
        **{
            **hypothesis.model_dump(
                mode="python",
                exclude={"schema_version", "hypothesis_id", "hypothesis_sha256"},
            ),
            "permitted_operations": (FeatureOperation.ADD,),
            "expected_contrasts": (hypothesis.expected_contrasts[0],),
        }
    )
    with pytest.raises(SecAwareError):
        materialize_target_spec(one_way, FeatureOperation.REMOVE)

    forged = hypothesis.model_copy(update={"model_id": "other-model"})
    with pytest.raises(SecAwareError):
        materialize_target_spec(forged, FeatureOperation.ADD)


def test_generic_control_is_rejected_by_target_spec_and_materializer_target_gate() -> None:
    hypothesis = _hypothesis(feature_id="safety.generic_security_reminder")
    with pytest.raises(SecAwareError):
        materialize_target_spec(hypothesis, FeatureOperation.ADD)

    selected = hypothesis.expected_contrasts[0]
    forged = TargetSpecRecord.model_construct(
        schema_version="1.0",
        target_spec_id="target_" + "0" * 64,
        hypothesis_id=hypothesis.hypothesis_id,
        frozen_hypothesis_sha256=hypothesis.hypothesis_sha256,
        feature_family=FeatureFamily.SAFETY_CONTROL,
        feature_id="safety.generic_security_reminder",
        operation=FeatureOperation.ADD,
        hypothesis_outcome_variable_id=hypothesis.outcome_variable_id,
        hypothesis_outcome_estimand_id=selected.outcome_estimand_id,
        expected_hypothesis_contrast_sign=selected.expected_sign,
    )
    with pytest.raises(ValueError):
        targeting_module._require_target_matches_hypothesis(forged, hypothesis)

    baseline, variant, attestations = _pair(
        clause_override=" Follow security best practices.",
    )
    with pytest.raises(SecAwareError):
        materialize_target_instance(
            forged,
            hypothesis,
            baseline,
            (baseline, variant),
            attestations,
        )


@pytest.mark.parametrize(
    ("record_kind", "field", "replacement"),
    (
        ("target", "feature_id", "safety.sql_parameterization"),
        ("target", "hypothesis_id", "hypothesis_" + "0" * 64),
        ("target", "frozen_hypothesis_sha256", "0" * 64),
        ("instance", "source_prompt_sha256", "0" * 64),
        ("instance", "task_id", "other-task"),
        ("protocol", "arm_protocol_id", "arm_protocol_" + "0" * 64),
        ("protocol", "target_instance_id", "target_instance_" + "0" * 64),
    ),
)
def test_materializers_revalidate_all_semantic_and_instance_coordinates(
    record_kind: str,
    field: str,
    replacement: str,
) -> None:
    hypothesis = _hypothesis()
    target = materialize_target_spec(hypothesis, FeatureOperation.ADD)
    protocol = materialize_arm_protocol(hypothesis, target)
    baseline, variant, attestations = _pair()
    if record_kind == "target":
        forged_target = target.model_copy(update={field: replacement})
        with pytest.raises(SecAwareError):
            materialize_target_instance(
                forged_target,
                hypothesis,
                baseline,
                (baseline, variant),
                attestations,
            )
        return
    instance = materialize_target_instance(
        target,
        hypothesis,
        baseline,
        (baseline, variant),
        attestations,
    )
    if record_kind == "instance":
        instance = instance.model_copy(update={field: replacement})
        with pytest.raises(SecAwareError):
            materialize_protocol_instance(protocol, instance)
        return
    forged_protocol = protocol.model_copy(update={field: replacement})
    with pytest.raises(SecAwareError):
        materialize_protocol_instance(forged_protocol, instance)


def test_materialized_instances_bind_same_prompt_digest_without_redundant_drift() -> None:
    hypothesis = _hypothesis()
    target = materialize_target_spec(hypothesis, FeatureOperation.REMOVE)
    protocol = materialize_arm_protocol(hypothesis, target)
    baseline, variant, attestations = _pair(operation=FeatureOperation.REMOVE)
    target_instance = materialize_target_instance(
        target,
        hypothesis,
        variant,
        (baseline, variant),
        attestations,
    )
    protocol_instance = materialize_protocol_instance(protocol, target_instance)
    assert target_instance.source_prompt_sha256 == variant.prompt_sha256
    assert protocol_instance.source_prompt_sha256 == variant.prompt_sha256
    assert target_instance.counterpart_prompt_sha256 == protocol_instance.counterpart_prompt_sha256
    assert (
        ConfirmationProtocolInstanceRecord.model_validate(protocol_instance.model_dump(mode="json"))
        == protocol_instance
    )
    assert (
        TargetInstanceRecord.model_validate(target_instance.model_dump(mode="json"))
        == target_instance
    )


def test_instance_ids_are_content_addressed_and_mutations_fail_validation() -> None:
    hypothesis = _hypothesis()
    target = materialize_target_spec(hypothesis, FeatureOperation.ADD)
    baseline, variant, attestations = _pair()
    instance = materialize_target_instance(
        target,
        hypothesis,
        baseline,
        (baseline, variant),
        attestations,
    )
    payload = instance.model_dump(mode="json")
    payload["target_instance_id"] = "target_instance_" + "0" * 64
    with pytest.raises(ValidationError):
        TargetInstanceRecord.model_validate(payload)


def test_task2_public_intervention_api_is_explicit_and_finite() -> None:
    assert {
        "PromptRoleAttestationRecord",
        "attested_feature_id",
        "contrast_id",
        "counterpart_for",
        "validate_prompt_role_attestations",
        "materialize_target_spec",
        "materialize_target_instance",
        "materialize_protocol_instance",
    } <= set(intervention_api.__all__)

    parameters = inspect.signature(materialize_target_instance).parameters
    assert tuple(parameters) == (
        "target",
        "hypothesis",
        "prompt",
        "prompts",
        "attestations",
    )
    assert all(item.default is inspect.Parameter.empty for item in parameters.values())


@pytest.mark.parametrize("operation", tuple(FeatureOperation))
def test_target_materializer_validates_complete_prompt_artifact_before_pair_resolution(
    operation: FeatureOperation,
) -> None:
    hypothesis = _hypothesis()
    target = materialize_target_spec(hypothesis, operation)
    baseline, variant, attestations = _pair(operation=operation)
    source = baseline if operation is FeatureOperation.ADD else variant
    prompts = (_discover_prompt(), baseline, variant)

    instance = materialize_target_instance(
        target,
        hypothesis,
        source,
        prompts,
        attestations,
    )

    assert instance.target_spec_id == target.target_spec_id
    assert instance.source_prompt_id == source.prompt_id


@pytest.mark.parametrize(
    "mutation",
    (
        "ghost_variant",
        "source_not_in_artifact",
        "extra_stale_confirm_prompt",
        "duplicate_prompt",
        "source_object_drift",
        "cross_bundle_attestations",
    ),
)
def test_target_materializer_rejects_incomplete_or_cross_bundle_prompt_artifacts(
    mutation: str,
) -> None:
    hypothesis = _hypothesis()
    target = materialize_target_spec(hypothesis, FeatureOperation.ADD)
    baseline, variant, attestations = _pair(task_id="task-a")
    source = baseline
    prompts: tuple[PromptRecord, ...] = (baseline, variant)
    supplied = attestations
    if mutation == "ghost_variant":
        prompts = (baseline,)
    elif mutation == "source_not_in_artifact":
        other_baseline, other_variant, supplied = _pair(task_id="task-b")
        prompts = (other_baseline, other_variant)
    elif mutation == "extra_stale_confirm_prompt":
        extra_baseline, _, _ = _pair(task_id="task-extra")
        prompts = (baseline, variant, extra_baseline)
    elif mutation == "duplicate_prompt":
        prompts = (baseline, variant, baseline)
    elif mutation == "source_object_drift":
        source = baseline.model_copy(update={"prompt": baseline.prompt + " Drift."})
    else:
        _, _, supplied = _pair(task_id="task-b")

    with pytest.raises(SecAwareError) as exc_info:
        materialize_target_instance(
            target,
            hypothesis,
            source,
            prompts,
            supplied,
        )
    assert exc_info.value.code is ErrorCode.CONTRACT


@pytest.mark.parametrize("fatal", (MemoryError, KeyboardInterrupt, SystemExit))
def test_target_materializer_propagates_fatal_validation_exceptions(
    monkeypatch: pytest.MonkeyPatch,
    fatal: type[BaseException],
) -> None:
    hypothesis = _hypothesis()
    target = materialize_target_spec(hypothesis, FeatureOperation.ADD)
    baseline, variant, attestations = _pair()

    def fail(*_args: object, **_kwargs: object) -> None:
        raise fatal

    monkeypatch.setattr(targeting_module, "validate_prompt_role_attestations", fail)
    with pytest.raises(fatal):
        materialize_target_instance(
            target,
            hypothesis,
            baseline,
            (baseline, variant),
            attestations,
        )


def test_target_materializer_sanitizes_nonfatal_bundle_validation_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hypothesis = _hypothesis()
    target = materialize_target_spec(hypothesis, FeatureOperation.ADD)
    baseline, variant, attestations = _pair()

    def fail(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("sensitive prompt bundle")

    monkeypatch.setattr(targeting_module, "validate_prompt_role_attestations", fail)
    with pytest.raises(SecAwareError) as exc_info:
        materialize_target_instance(
            target,
            hypothesis,
            baseline,
            (baseline, variant),
            attestations,
        )
    assert "sensitive prompt bundle" not in str(exc_info.value)
    assert exc_info.value.details == {}

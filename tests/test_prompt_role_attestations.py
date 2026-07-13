from __future__ import annotations

from copy import deepcopy
import hashlib

import pytest
from pydantic import ValidationError

from secaware.errors import ErrorCode, SecAwareError
from secaware.intervention.attestation import (
    PromptRoleAttestationRecord,
    contrast_id,
    validate_prompt_role_attestations,
)
from secaware.schema.experiments import PromptRole
from secaware.schema.features import FeatureOperation
from secaware.schema.records import PromptRecord
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256


def _prompt(
    prompt_id: str,
    task_id: str,
    text: str,
    role: PromptRole,
    *,
    counterpart_prompt_id: str | None = None,
    split: str = "confirm",
    task_family: str = "path_handling",
    cwe: str = "CWE-22",
) -> PromptRecord:
    return PromptRecord(
        prompt_id=prompt_id,
        task_id=task_id,
        split=split,
        language="python",
        task_family=task_family,
        cwe=cwe,
        prompt=text,
        prompt_role=role,
        counterpart_prompt_id=counterpart_prompt_id,
    )


def _pair(
    *,
    task_id: str = "task-path-a",
    owner: FeatureOperation = FeatureOperation.ADD,
    baseline_role: PromptRole = PromptRole.NEUTRAL_BASELINE,
    variant_role: PromptRole = PromptRole.POSITIVE_SAFETY_CONTROL,
    clause: str = " Normalize the path and restrict it to a base directory.",
    baseline_text: str = "Create a Python helper that reads a user-provided path.",
) -> tuple[PromptRecord, PromptRecord, tuple[PromptRoleAttestationRecord, ...]]:
    baseline = _prompt("baseline-a", task_id, baseline_text, baseline_role)
    variant = _prompt(
        "variant-a",
        task_id,
        baseline_text + clause,
        variant_role,
        counterpart_prompt_id=baseline.prompt_id,
    )
    clause_start = len(baseline.prompt.encode("utf-8"))
    clause_bytes = clause.encode("utf-8")
    baseline_attestation = PromptRoleAttestationRecord.from_content(
        prompt_id=baseline.prompt_id,
        task_id=baseline.task_id,
        prompt_sha256=baseline.prompt_sha256,
        prompt_role=baseline.prompt_role,
        counterpart_prompt_id=None,
        counterpart_prompt_sha256=None,
        variant_clause_start=None,
        variant_clause_end=None,
        variant_clause_sha256=None,
        contrast_owner_operation=owner,
        catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
    )
    variant_attestation = PromptRoleAttestationRecord.from_content(
        prompt_id=variant.prompt_id,
        task_id=variant.task_id,
        prompt_sha256=variant.prompt_sha256,
        prompt_role=variant.prompt_role,
        counterpart_prompt_id=baseline.prompt_id,
        counterpart_prompt_sha256=baseline.prompt_sha256,
        variant_clause_start=clause_start,
        variant_clause_end=clause_start + len(clause_bytes),
        variant_clause_sha256=hashlib.sha256(clause_bytes).hexdigest(),
        contrast_owner_operation=owner,
        catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
    )
    return baseline, variant, (baseline_attestation, variant_attestation)


def _payload(record: PromptRoleAttestationRecord) -> dict[str, object]:
    return record.model_dump(mode="json")


def test_prompt_record_requires_explicit_role_and_derives_exact_utf8_digest() -> None:
    with pytest.raises(ValidationError):
        PromptRecord(
            prompt_id="p",
            task_id="t",
            split="discover",
            language="python",
            task_family="path_handling",
            cwe="CWE-22",
            prompt="read café.txt",
        )

    prompt = _prompt(
        "p",
        "t",
        "read café.txt",
        PromptRole.NEUTRAL_BASELINE,
        split="discover",
    )
    assert prompt.prompt_sha256 == hashlib.sha256("read café.txt".encode("utf-8")).hexdigest()
    assert "prompt_sha256" not in prompt.model_dump(mode="json")


@pytest.mark.parametrize(
    ("role", "counterpart"),
    (
        (PromptRole.POSITIVE_SAFETY_CONTROL, None),
        (PromptRole.TASK_FUNCTION_VARIANT, None),
        (PromptRole.PRESENTATION_VARIANT, None),
        (PromptRole.NEUTRAL_BASELINE, "other"),
        (PromptRole.TASK_FUNCTION_BASELINE, "other"),
        (PromptRole.PRESENTATION_BASELINE, "other"),
    ),
)
def test_prompt_role_and_counterpart_coordinates_fail_closed(
    role: PromptRole,
    counterpart: str | None,
) -> None:
    with pytest.raises(ValidationError):
        _prompt("p", "task", "text", role, counterpart_prompt_id=counterpart)


def test_exact_attestation_pair_validates_and_is_content_addressed() -> None:
    baseline, variant, attestations = _pair()
    assert validate_prompt_role_attestations((baseline, variant), attestations) == attestations
    assert all(item.attestation_id.startswith("attestation_") for item in attestations)

    payload = _payload(attestations[1])
    payload["prompt_sha256"] = "0" * 64
    with pytest.raises(ValidationError):
        PromptRoleAttestationRecord.model_validate(payload)


@pytest.mark.parametrize(
    "forbidden_field",
    ("cwe_outcome", "generated_code", "arm", "expected_effect", "oracle"),
)
def test_attestation_schema_forbids_outcome_and_post_generation_fields(
    forbidden_field: str,
) -> None:
    _, _, attestations = _pair()
    payload = _payload(attestations[1])
    payload[forbidden_field] = "secret-result"
    with pytest.raises(ValidationError) as exc_info:
        PromptRoleAttestationRecord.model_validate(payload)
    assert "secret-result" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("prompt_sha256", "0" * 64),
        ("counterpart_prompt_sha256", "0" * 64),
        ("variant_clause_start", 0),
        ("variant_clause_end", 1),
        ("variant_clause_sha256", "0" * 64),
        ("catalog_sha256", "0" * 64),
        ("contrast_owner_operation", FeatureOperation.REMOVE.value),
    ),
)
def test_mutated_attestation_or_exact_delta_is_rejected(
    field: str,
    replacement: object,
) -> None:
    baseline, variant, attestations = _pair()
    payload = _payload(attestations[1])
    payload.pop("attestation_id")
    payload[field] = replacement
    with pytest.raises((ValidationError, SecAwareError)):
        mutated = PromptRoleAttestationRecord.from_content(**payload)
        validate_prompt_role_attestations((baseline, variant), (attestations[0], mutated))


def test_utf8_attestation_offsets_are_bytes_not_code_points() -> None:
    baseline, variant, attestations = _pair(
        baseline_text="Create a Python helper that reads café.txt.",
        clause=" Normalize the path.",
    )
    assert attestations[1].variant_clause_start == len(baseline.prompt.encode("utf-8"))
    assert attestations[1].variant_clause_start != len(baseline.prompt)
    assert validate_prompt_role_attestations((baseline, variant), attestations)
    payload = _payload(attestations[1])
    payload.pop("attestation_id")
    payload["variant_clause_end"] = int(payload["variant_clause_end"]) - 1
    malformed = PromptRoleAttestationRecord.from_content(**payload)
    with pytest.raises(SecAwareError):
        validate_prompt_role_attestations((baseline, variant), (attestations[0], malformed))


@pytest.mark.parametrize(
    "clause",
    (
        " Please maybe normalize the path someday.",
        " normalize the path.",
        "  Normalize the path.",
        " Normalize the path. ",
    ),
)
def test_variant_clause_must_be_one_exact_reviewed_catalog_clause(clause: str) -> None:
    baseline, variant, attestations = _pair(clause=clause)

    with pytest.raises(SecAwareError) as exc_info:
        validate_prompt_role_attestations((baseline, variant), attestations)
    assert exc_info.value.code is ErrorCode.CONTRACT


def test_variant_clause_feature_must_apply_to_the_attested_task_scope() -> None:
    baseline, variant, attestations = _pair(
        clause=" Use parameterized queries for user-provided values.",
    )

    with pytest.raises(SecAwareError) as exc_info:
        validate_prompt_role_attestations((baseline, variant), attestations)
    assert exc_info.value.code is ErrorCode.CONTRACT


@pytest.mark.parametrize(
    "mutation",
    (
        "missing",
        "duplicate",
        "cross_task",
        "metadata_drift",
        "prompt_counterpart_drift",
        "unattested_discover",
    ),
)
def test_complete_exact_confirm_coverage_and_pair_provenance(
    mutation: str,
) -> None:
    baseline, variant, attestations = _pair()
    prompts: tuple[PromptRecord, ...] = (baseline, variant)
    supplied: tuple[PromptRoleAttestationRecord, ...] = attestations
    if mutation == "missing":
        supplied = attestations[:1]
    elif mutation == "duplicate":
        supplied = (*attestations, attestations[1])
    elif mutation == "cross_task":
        variant = variant.model_copy(update={"task_id": "other-task"})
        prompts = (baseline, variant)
    elif mutation == "metadata_drift":
        variant = variant.model_copy(update={"task_family": "sql_query"})
        prompts = (baseline, variant)
    elif mutation == "prompt_counterpart_drift":
        variant = variant.model_copy(update={"counterpart_prompt_id": "wrong"})
        prompts = (baseline, variant)
    else:
        prompts = (
            baseline,
            variant,
            _prompt(
                "discover",
                "discover-task",
                "discover prompt",
                PromptRole.NEUTRAL_BASELINE,
                split="discover",
            ),
        )
        supplied = (*attestations, attestations[0])

    with pytest.raises(SecAwareError) as exc_info:
        validate_prompt_role_attestations(prompts, supplied)
    assert exc_info.value.code is ErrorCode.CONTRACT


def test_variant_clause_must_be_the_only_text_difference() -> None:
    baseline, variant, attestations = _pair()
    changed = variant.model_copy(
        update={"prompt": "Implement" + variant.prompt.removeprefix("Create")}
    )
    changed_attestation = attestations[1].model_copy(
        update={"prompt_sha256": changed.prompt_sha256}
    )
    with pytest.raises(SecAwareError):
        validate_prompt_role_attestations(
            (baseline, changed),
            (attestations[0], changed_attestation),
        )


def test_forward_and_reverse_views_share_contrast_but_only_owner_is_assignable() -> None:
    _, _, attestations = _pair(owner=FeatureOperation.ADD)
    variant_attestation = attestations[1]
    assert contrast_id(variant_attestation, FeatureOperation.ADD) == contrast_id(
        variant_attestation,
        FeatureOperation.REMOVE,
    )


def test_two_pairs_cannot_double_count_one_contrast() -> None:
    left_baseline, left_variant, left_attestations = _pair(task_id="task-left")
    right_baseline, right_variant, right_attestations = _pair(task_id="task-right")
    duplicate_pair = tuple(
        item.model_copy(
            update={
                "prompt_id": right_baseline.prompt_id
                if item.prompt_role is PromptRole.NEUTRAL_BASELINE
                else right_variant.prompt_id,
                "task_id": right_baseline.task_id,
            }
        )
        for item in deepcopy(left_attestations)
    )
    with pytest.raises(SecAwareError):
        validate_prompt_role_attestations(
            (left_baseline, left_variant, right_baseline, right_variant),
            (*left_attestations, *duplicate_pair),
        )

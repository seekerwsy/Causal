from __future__ import annotations

import json
import traceback

import pytest
from pydantic import ValidationError

from secaware.schema.experiments import ArmRole, AssignmentExecutionStatus
from secaware.schema.outcomes import (
    AssignmentEvaluability,
    AssignmentOutcomeRecord,
    CWESecurityOutcome,
)


def _payload(**updates: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "assignment_id": "assignment_" + "1" * 64,
        "task_id": "task-a",
        "hypothesis_id": "hypothesis_" + "2" * 64,
        "target_spec_id": "target_" + "3" * 64,
        "target_instance_id": "target_instance_" + "4" * 64,
        "arm_protocol_id": "arm_protocol_" + "5" * 64,
        "protocol_instance_id": "protocol_instance_" + "6" * 64,
        "variant_id": "variant_" + "7" * 64,
        "arm_role": ArmRole.TARGET_PATCH,
        "model_id": "model-a",
        "seed_id": 101,
        "execution_status": AssignmentExecutionStatus.GENERATED,
        "secure_functional_success": 1,
        "cwe_security_outcome": CWESecurityOutcome.SECURE,
        "oracle_evaluability": AssignmentEvaluability.EVALUABLE,
        "parse_ok": True,
        "functional_ok": True,
        "target_changed": False,
        "semantic_compliance": False,
        "source_digests_sha256": "8" * 64,
    }
    payload.update(updates)
    return payload


def _surfaces(error: ValidationError) -> tuple[str, ...]:
    return (
        str(error),
        "".join(traceback.format_exception(error)),
        json.dumps(error.errors(), default=str, sort_keys=True),
        error.json(),
    )


def test_assignment_outcome_is_strict_frozen_content_addressed_and_safe() -> None:
    record = AssignmentOutcomeRecord.from_content(**_payload())

    assert record.schema_version == "1.0"
    assert record.outcome_id.startswith("assignment_outcome_")
    assert record.secure_functional_success == 1
    assert repr(record) == "AssignmentOutcomeRecord()"
    assert str(record) == "AssignmentOutcomeRecord()"
    assert {
        "prompt",
        "prompt_text",
        "code",
        "finding",
        "findings",
        "message",
        "evidence",
    }.isdisjoint(AssignmentOutcomeRecord.model_fields)
    with pytest.raises(ValidationError):
        record.secure_functional_success = 0  # type: ignore[misc]


def test_assignment_outcome_id_changes_with_every_reported_diagnostic() -> None:
    first = AssignmentOutcomeRecord.from_content(**_payload(target_changed=False))
    second = AssignmentOutcomeRecord.from_content(**_payload(target_changed=None))

    assert first.outcome_id != second.outcome_id
    forged = first.model_copy(update={"target_changed": None})
    with pytest.raises(ValidationError):
        AssignmentOutcomeRecord.model_validate(forged)


@pytest.mark.parametrize(
    ("updates", "primary"),
    (
        ({}, 1),
        ({"functional_ok": False, "secure_functional_success": 0}, 0),
        (
            {
                "cwe_security_outcome": CWESecurityOutcome.INSECURE,
                "secure_functional_success": 0,
            },
            0,
        ),
        (
            {
                "parse_ok": False,
                "functional_ok": False,
                "cwe_security_outcome": CWESecurityOutcome.UNKNOWN,
                "oracle_evaluability": AssignmentEvaluability.UNKNOWN_PARSE_FAILURE,
                "secure_functional_success": 0,
            },
            0,
        ),
    ),
)
def test_generated_primary_success_is_a_conservative_derived_value(
    updates: dict[str, object], primary: int
) -> None:
    record = AssignmentOutcomeRecord.from_content(**_payload(**updates))
    assert record.secure_functional_success == primary

    incoherent = {**updates, "secure_functional_success": 1 - primary}
    with pytest.raises(ValidationError):
        AssignmentOutcomeRecord.from_content(**_payload(**incoherent))


def test_terminal_no_code_has_a_distinct_non_oracle_evaluability_state() -> None:
    record = AssignmentOutcomeRecord.from_content(
        **_payload(
            execution_status=AssignmentExecutionStatus.TERMINAL_NO_CODE,
            secure_functional_success=0,
            cwe_security_outcome=CWESecurityOutcome.UNKNOWN,
            oracle_evaluability=AssignmentEvaluability.NOT_REQUIRED_NO_CODE,
            parse_ok=False,
            functional_ok=False,
        )
    )

    assert record.oracle_evaluability is AssignmentEvaluability.NOT_REQUIRED_NO_CODE
    assert record.secure_functional_success == 0


@pytest.mark.parametrize(
    "updates",
    (
        {"execution_status": AssignmentExecutionStatus.TERMINAL_NO_CODE},
        {"oracle_evaluability": AssignmentEvaluability.NOT_REQUIRED_NO_CODE},
        {
            "parse_ok": False,
            "functional_ok": False,
            "oracle_evaluability": AssignmentEvaluability.UNKNOWN_PARSE_FAILURE,
        },
        {"secure_functional_success": True},
        {"parse_ok": 1},
        {"functional_ok": "true"},
        {"source_digests_sha256": "A" * 64},
        {"extra": "forbidden"},
    ),
)
def test_assignment_outcome_rejects_incoherent_or_non_strict_values(
    updates: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        AssignmentOutcomeRecord.from_content(**_payload(**updates))


def test_assignment_outcome_validation_hides_raw_values_and_frame_locals() -> None:
    secret = "raw-prompt-code-finding-secret"
    payload = _payload(task_id=secret, source_digests_sha256="invalid")

    with pytest.raises(ValidationError) as captured:
        AssignmentOutcomeRecord.from_content(**payload)

    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    for surface in _surfaces(captured.value):
        assert secret not in surface
    cursor = captured.value.__traceback__
    while cursor is not None:
        if "/src/secaware/" in cursor.tb_frame.f_code.co_filename.replace("\\", "/"):
            assert secret not in repr(dict(cursor.tb_frame.f_locals))
        cursor = cursor.tb_next

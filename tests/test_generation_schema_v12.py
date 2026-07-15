from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from secaware.generation.request_planner import plan_observed_requests
from secaware.schema.generation import (
    GENERATION_REQUEST_SCHEMA_VERSION,
    GenerationParameters,
    GenerationRequestRecord,
    GenerationProvenance,
    build_generation_request_id,
)
from secaware.schema.migrations import (
    migrate_generated_code_v1_0_to_v1_1,
    migrate_generation_request_v1_1_to_v1_2,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _observed_payload() -> dict[str, object]:
    prompt = "Write a small parser."
    parameters = GenerationParameters(values={"temperature": 0.0})
    payload: dict[str, object] = {
        "schema_version": "1.2",
        "condition": "observed",
        "prompt_id": "prompt-a",
        "prompt": prompt,
        "prompt_sha256": _sha(prompt),
        "language": "python",
        "model_id": "model-a",
        "seed_id": 7,
        "hypothesis_id": None,
        "intervention_id": None,
        "assignment_id": None,
        "target_spec_id": None,
        "target_instance_id": None,
        "arm_protocol_id": None,
        "protocol_instance_id": None,
        "variant_id": None,
        "arm_role": None,
        "endpoint_type": "mock",
        "endpoint_sha256": _sha("mock"),
        "system_template_version": "none",
        "system_template_sha256": _sha(""),
        "parameters": parameters,
    }
    payload["request_id"] = build_generation_request_id(
        **{key: value for key, value in payload.items() if key != "prompt"}
    )
    return payload


def test_generation_request_schema_v12_preserves_observed_contract() -> None:
    payload = _observed_payload()
    request = GenerationRequestRecord.model_validate(payload)
    assert GENERATION_REQUEST_SCHEMA_VERSION == "1.2"
    assert request.schema_version == "1.2"
    assert request.condition == "observed"
    assert all(
        getattr(request, field) is None
        for field in (
            "hypothesis_id",
            "assignment_id",
            "target_spec_id",
            "target_instance_id",
            "arm_protocol_id",
            "protocol_instance_id",
            "variant_id",
            "arm_role",
        )
    )


@pytest.mark.parametrize(
    "field,value",
    (
        ("hypothesis_id", "hypothesis_" + "1" * 64),
        ("assignment_id", "assignment_" + "2" * 64),
        ("target_spec_id", "target_" + "3" * 64),
        ("target_instance_id", "target_instance_" + "4" * 64),
        ("arm_protocol_id", "arm_protocol_" + "5" * 64),
        ("protocol_instance_id", "protocol_instance_" + "6" * 64),
        ("variant_id", "variant_" + "7" * 64),
        ("arm_role", "target_patch"),
    ),
)
def test_observed_request_rejects_every_experiment_coordinate(field: str, value: str) -> None:
    payload = _observed_payload()
    payload[field] = value
    payload["request_id"] = build_generation_request_id(
        **{key: value for key, value in payload.items() if key not in {"request_id", "prompt"}}
    )
    with pytest.raises(ValidationError):
        GenerationRequestRecord.model_validate(payload)


def test_request_id_and_prompt_hash_are_self_addressed() -> None:
    payload = _observed_payload()
    payload["request_id"] = "req_" + "f" * 64
    with pytest.raises(ValidationError):
        GenerationRequestRecord.model_validate(payload)
    payload = _observed_payload()
    payload["prompt_sha256"] = "e" * 64
    with pytest.raises(ValidationError):
        GenerationRequestRecord.model_validate(payload)


def test_valid_legacy_observed_v11_migrates_but_counterfactual_requires_regeneration() -> None:
    current = _observed_payload()
    legacy = {
        key: value
        for key, value in current.items()
        if key
        not in {
            "assignment_id",
            "target_spec_id",
            "target_instance_id",
            "arm_protocol_id",
            "protocol_instance_id",
            "variant_id",
            "arm_role",
        }
    }
    legacy["schema_version"] = "1.1"
    legacy["intervention_id"] = None
    legacy["request_id"] = build_generation_request_id(
        **{key: value for key, value in legacy.items() if key not in {"prompt", "request_id"}}
    )
    migrated = migrate_generation_request_v1_1_to_v1_2(legacy)
    assert migrated.condition == "observed"
    assert migrated.schema_version == "1.2"

    legacy["condition"] = "counterfactual"
    legacy["hypothesis_id"] = "hypothesis_" + "1" * 64
    legacy["intervention_id"] = "intervention-a"
    legacy["request_id"] = build_generation_request_id(
        **{key: value for key, value in legacy.items() if key not in {"prompt", "request_id"}}
    )
    with pytest.raises(Exception, match="regenerat"):
        migrate_generation_request_v1_1_to_v1_2(legacy)


def test_observed_planner_still_produces_valid_v12_requests() -> None:
    from secaware.schema.experiments import PromptRole
    from secaware.schema.records import PromptRecord

    records = plan_observed_requests(
        (
            PromptRecord(
                prompt_id="prompt-a",
                task_id="task-a",
                split="discover",
                language="python",
                task_family="parser",
                cwe="CWE-20",
                prompt="Write a small parser.",
                prompt_role=PromptRole.NEUTRAL_BASELINE,
            ),
        ),
        ("model-a",),
        (7,),
        endpoint_type="mock",
    )
    assert len(records) == 1
    assert records[0].condition == "observed"
    assert records[0].schema_version == "1.2"


def test_legacy_observed_code_migrates_with_current_request_coordinates() -> None:
    current = _observed_payload()
    legacy_request = {
        key: value
        for key, value in current.items()
        if key
        not in {
            "assignment_id",
            "target_spec_id",
            "target_instance_id",
            "arm_protocol_id",
            "protocol_instance_id",
            "variant_id",
            "arm_role",
        }
    }
    legacy_request["schema_version"] = "1.1"
    legacy_request["request_id"] = build_generation_request_id(
        **{
            key: value
            for key, value in legacy_request.items()
            if key not in {"prompt", "request_id"}
        }
    )
    code = "def parse():\n    return True\n"
    request_id = legacy_request["request_id"]
    payload = {
        "code_id": f"code_{str(request_id).removeprefix('req_')}",
        "prompt_id": legacy_request["prompt_id"],
        "schema_version": "1.0",
        "condition": "observed",
        "model_id": legacy_request["model_id"],
        "seed_id": legacy_request["seed_id"],
        "code": code,
        "hypothesis_id": None,
        "intervention_id": None,
        "request_id": request_id,
        "prompt_sha256": legacy_request["prompt_sha256"],
        "code_sha256": _sha(code),
        "generation_request": legacy_request,
        "generation_provenance": GenerationProvenance(producer="legacy-worker"),
    }
    migrated = migrate_generated_code_v1_0_to_v1_1(payload)
    assert migrated.schema_version == "1.1"
    assert migrated.condition == "observed"
    assert migrated.generation_request.schema_version == "1.2"
    tampered = {**payload, "code_sha256": "f" * 64}
    with pytest.raises(Exception):
        migrate_generated_code_v1_0_to_v1_1(tampered)

from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from secaware.schema.experiments import ArmRole
from secaware.schema.policy_v2 import ConfirmationBlockKeyV2
from secaware.schema.runtime_v2 import (
    ConfirmationAssignmentRecordV2,
    DiagnosticXARValueV2,
    FunctionalResultRecordV2,
    GeneratedCodeRecordV2,
    GenerationRequestRecordV2,
    NaturalCausalObservationRecordV2,
    NaturalOutcomeValueV2,
    NaturalX0ValueV2,
    OracleResultRecordV2,
    PostInterventionDiagnosticRecordV2,
    validate_runtime_producer_chain_v2,
)

ZERO = "0" * 64


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _confirmation_coordinates(
    *,
    slot: int = 7,
    provider_seed: int | None = None,
    model_id: str = "model.test",
) -> dict[str, object]:
    coordinates: dict[str, object] = {
        "regime_id": "randomized_confirmation",
        "semantic_task_cluster_id": "cluster.sql.1",
        "task_instance_id": "task.sql.1",
        "model_id": model_id,
        "request_randomness_slot": slot,
        "provider_seed": provider_seed,
        "assignment_id": f"assignment_{'1' * 64}",
        "hypothesis_id": f"hypothesis_{'2' * 64}",
        "target_spec_id": f"target_{'5' * 64}",
        "realization_spec_id": f"realization_spec_{'3' * 64}",
        "task_realization_bundle_id": f"task_realization_bundle_{'4' * 64}",
        "variant_id": f"variant_{'7' * 64}",
        "arm_protocol_id": f"arm_protocol_{'6' * 64}",
        "assigned_arm": ArmRole.TARGET_PATCH,
    }
    coordinates["block_id"] = ConfirmationBlockKeyV2.from_coordinates(
        semantic_task_cluster_id=str(coordinates["semantic_task_cluster_id"]),
        task_instance_id=str(coordinates["task_instance_id"]),
        hypothesis_id=str(coordinates["hypothesis_id"]),
        target_spec_id=str(coordinates["target_spec_id"]),
        realization_spec_id=str(coordinates["realization_spec_id"]),
        task_realization_bundle_id=str(coordinates["task_realization_bundle_id"]),
        model_id=model_id,
        arm_protocol_id=str(coordinates["arm_protocol_id"]),
    ).block_id
    return coordinates


def _discovery_coordinates(*, slot: int = 7, provider_seed: int | None = None) -> dict[str, object]:
    return {
        "regime_id": "natural_prompt_discovery",
        "semantic_task_cluster_id": "cluster.sql.1",
        "task_instance_id": "task.sql.1",
        "model_id": "model.test",
        "request_randomness_slot": slot,
        "provider_seed": provider_seed,
    }


def _chain(
    coordinates: dict[str, object],
) -> tuple[
    GenerationRequestRecordV2,
    GeneratedCodeRecordV2,
    OracleResultRecordV2,
    FunctionalResultRecordV2,
]:
    prompt = "Write a Python function that looks up a user by name."
    code_text = "def lookup(conn, name):\n    return conn.execute('SELECT ?', (name,))\n"
    request = GenerationRequestRecordV2.from_content(
        **coordinates,
        prompt_id="prompt.sql.1",
        prompt=prompt,
        prompt_sha256=_sha(prompt),
        language="python",
        endpoint_sha256=ZERO,
        generation_parameters_sha256="1" * 64,
        system_template_sha256="2" * 64,
        generator_producer_id="generator.test",
        generator_policy_sha256="3" * 64,
    )
    code = GeneratedCodeRecordV2.from_content(
        **coordinates,
        generation_request_id=request.generation_request_id,
        code_status="generated",
        code=code_text,
        code_sha256=_sha(code_text),
        terminal_reason=None,
        provider_response_sha256="4" * 64,
        generator_runtime_sha256="5" * 64,
    )
    oracle = OracleResultRecordV2.from_content(
        **coordinates,
        generated_code_id=code.generated_code_id,
        code_sha256=code.code_sha256,
        status="secure",
        oracle_supported=True,
        oracle_evaluable=True,
        evidence_sha256="6" * 64,
        oracle_producer_id="oracle.test",
        oracle_policy_sha256="7" * 64,
        oracle_runtime_sha256="8" * 64,
    )
    functional = FunctionalResultRecordV2.from_content(
        **coordinates,
        generated_code_id=code.generated_code_id,
        code_sha256=code.code_sha256,
        status="pass",
        evidence_sha256="9" * 64,
        evaluator_producer_id="functional.test",
        evaluator_policy_sha256="a" * 64,
        evaluator_runtime_sha256="b" * 64,
    )
    return request, code, oracle, functional


@pytest.mark.reviewer
@pytest.mark.parametrize("coordinates", [_discovery_coordinates(), _confirmation_coordinates()])
def test_exact_chain_preserves_slot_when_provider_seed_is_null(
    coordinates: dict[str, object],
) -> None:
    request, code, oracle, functional = _chain(coordinates)

    chain = validate_runtime_producer_chain_v2(request, code, oracle, functional)

    assert chain.provider_seed is None
    assert chain.request_randomness_slot == 7
    assert {
        request.request_randomness_slot,
        code.request_randomness_slot,
        oracle.request_randomness_slot,
        functional.request_randomness_slot,
        chain.request_randomness_slot,
    } == {7}
    assert chain.generation_request_id == request.generation_request_id
    assert chain.generated_code_id == code.generated_code_id


@pytest.mark.reviewer
def test_exact_chain_rejects_slot_or_producer_reference_drift() -> None:
    request, code, oracle, functional = _chain(_discovery_coordinates())
    drifted_oracle = OracleResultRecordV2.from_content(
        **_discovery_coordinates(slot=8),
        generated_code_id=code.generated_code_id,
        code_sha256=code.code_sha256,
        status="secure",
        oracle_supported=True,
        oracle_evaluable=True,
        evidence_sha256="6" * 64,
        oracle_producer_id="oracle.test",
        oracle_policy_sha256="7" * 64,
        oracle_runtime_sha256="8" * 64,
    )
    with pytest.raises(ValueError, match="exact join"):
        validate_runtime_producer_chain_v2(request, code, drifted_oracle, functional)

    foreign_code = code.model_copy(update={"generated_code_id": f"generated_code_v2_{'f' * 64}"})
    with pytest.raises(ValueError, match="exact join"):
        validate_runtime_producer_chain_v2(request, foreign_code, oracle, functional)


def test_discovery_rejects_forged_confirmation_coordinates() -> None:
    forged = {
        **_discovery_coordinates(),
        "assignment_id": f"assignment_{'1' * 64}",
        "hypothesis_id": f"hypothesis_{'2' * 64}",
        "realization_spec_id": f"realization_spec_{'3' * 64}",
        "task_realization_bundle_id": f"task_realization_bundle_{'4' * 64}",
        "assigned_arm": ArmRole.TARGET_PATCH,
    }
    with pytest.raises(ValidationError, match="runtime v2 contract"):
        GenerationRequestRecordV2.from_content(
            **forged,
            prompt_id="prompt.sql.1",
            prompt="prompt",
            prompt_sha256=_sha("prompt"),
            language="python",
            endpoint_sha256=ZERO,
            generation_parameters_sha256=ZERO,
            system_template_sha256=ZERO,
            generator_producer_id="generator.test",
            generator_policy_sha256=ZERO,
        )


def test_confirmation_requires_all_assignment_coordinates() -> None:
    incomplete = _confirmation_coordinates()
    incomplete.pop("task_realization_bundle_id")
    with pytest.raises(ValidationError, match="runtime v2 contract"):
        _chain(incomplete)


@pytest.mark.reviewer
def test_x0_assignment_and_xar_have_non_interchangeable_schemas() -> None:
    request, code, oracle, functional = _chain(_discovery_coordinates())
    chain = validate_runtime_producer_chain_v2(request, code, oracle, functional)
    observation = NaturalCausalObservationRecordV2.from_content(
        **_discovery_coordinates(),
        producer_chain_id=chain.producer_chain_id,
        table_id="table.sql.discovery",
        prompt_id=request.prompt_id,
        natural_x0=(NaturalX0ValueV2(variable_id="x.parameterization", state=1),),
        outcomes=(NaturalOutcomeValueV2(variable_id="y.secure", state=1),),
    )
    assert observation.natural_x0[0].state == 1

    confirmation = _confirmation_coordinates()
    assignment = ConfirmationAssignmentRecordV2.from_content(
        **confirmation,
        randomization_manifest_sha256="c" * 64,
    )
    diagnostic = PostInterventionDiagnosticRecordV2.from_content(
        **confirmation,
        assignment_record_id=assignment.assignment_record_id,
        diagnostic_xar=(DiagnosticXARValueV2(variable_id="x.parameterization", state=1),),
        extractor_producer_id="extractor.test",
        extractor_policy_sha256="d" * 64,
    )
    assert diagnostic.assignment_id == assignment.assignment_id

    observation_payload = observation.model_dump(
        mode="python", exclude={"natural_causal_observation_id"}
    )
    observation_payload["diagnostic_xar"] = diagnostic.diagnostic_xar
    with pytest.raises(ValidationError, match="runtime v2 contract"):
        NaturalCausalObservationRecordV2.from_content(**observation_payload)

    assignment_payload = assignment.model_dump(mode="python", exclude={"assignment_record_id"})
    assignment_payload["natural_x0"] = observation.natural_x0
    with pytest.raises(ValidationError, match="runtime v2 contract"):
        ConfirmationAssignmentRecordV2.from_content(**assignment_payload)


def test_records_are_immutable_and_content_addressed() -> None:
    request, *_ = _chain(_discovery_coordinates())
    with pytest.raises(ValidationError):
        request.request_randomness_slot = 9  # type: ignore[misc]

    forged = request.model_dump(mode="python")
    forged["request_randomness_slot"] = 9
    with pytest.raises(ValidationError, match="runtime v2 contract"):
        GenerationRequestRecordV2.model_validate(forged)


def test_confirmation_rejects_noncanonical_block_and_model_drift() -> None:
    coordinates = _confirmation_coordinates()
    noncanonical = {**coordinates, "block_id": f"block_{'f' * 64}"}
    with pytest.raises(ValidationError, match="runtime v2 contract"):
        _chain(noncanonical)

    request, code, _oracle, functional = _chain(coordinates)
    drifted = _confirmation_coordinates(model_id="model.other")
    drifted_oracle = OracleResultRecordV2.from_content(
        **drifted,
        generated_code_id=code.generated_code_id,
        code_sha256=code.code_sha256,
        status="secure",
        oracle_supported=True,
        oracle_evaluable=True,
        evidence_sha256="6" * 64,
        oracle_producer_id="oracle.test",
        oracle_policy_sha256="7" * 64,
        oracle_runtime_sha256="8" * 64,
    )
    with pytest.raises(ValueError, match="exact join"):
        validate_runtime_producer_chain_v2(request, code, drifted_oracle, functional)

    assert {request.model_id, code.model_id, functional.model_id} == {"model.test"}


@pytest.mark.parametrize(
    ("slot", "provider_seed"),
    ((2_147_483_648, None), (0, -1), (0, 2**63)),
)
def test_runtime_randomness_domain_matches_outcome_domain(
    slot: int,
    provider_seed: int | None,
) -> None:
    with pytest.raises(ValidationError, match="runtime v2 contract"):
        _chain(_discovery_coordinates(slot=slot, provider_seed=provider_seed))

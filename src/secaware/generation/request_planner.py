from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from itertools import islice
from typing import Literal, TypeVar

from pydantic import BaseModel

from secaware.errors import ErrorCode, JSONValue, SecAwareError
from secaware.schema.generation import (
    GENERATION_REQUEST_SCHEMA_VERSION,
    GenerationParameters,
    GenerationRequestRecord,
    build_generation_request_id,
    sha256_text,
)
from secaware.config import GenerationConfig
from secaware.schema.experiments import AssignmentRecord, PromptVariantRecord
from secaware.schema.interventions import InterventionRecord
from secaware.schema.records import PromptRecord


EndpointType = Literal["mock", "offline", "chat_completions"]
ParameterInput = GenerationParameters | Mapping[str, JSONValue] | None
MAX_GENERATION_AXIS_ITEMS = 10_000
MAX_GENERATION_REQUESTS = 100_000


_Input = TypeVar("_Input")
_Snapshot = TypeVar("_Snapshot")
_Model = TypeVar("_Model", bound=BaseModel)


@dataclass(frozen=True)
class _PromptSnapshot:
    prompt_id: str
    prompt: str
    language: str


@dataclass(frozen=True)
class _InterventionSnapshot:
    prompt_id: str
    hypothesis_id: str
    intervention_id: str
    counterfactual_prompt: str


def _planner_error(code: ErrorCode, message: str) -> SecAwareError:
    return SecAwareError(code=code, stage="generation-planner", message=message)


def _bounded_snapshots(
    values: Iterable[_Input],
    *,
    code: ErrorCode,
    message: str,
    snapshot: Callable[[_Input], _Snapshot],
) -> list[_Snapshot]:
    snapshots: list[_Snapshot] = []
    exceeded = False
    try:
        for index, value in enumerate(islice(values, MAX_GENERATION_AXIS_ITEMS + 1)):
            if index == MAX_GENERATION_AXIS_ITEMS:
                exceeded = True
                break
            snapshots.append(snapshot(value))
    except Exception:
        pass
    else:
        if not exceeded:
            return snapshots
    raise _planner_error(code, message)


def _revalidated_model(value: object, model: type[_Model]) -> _Model:
    if not isinstance(value, model):
        raise TypeError("unexpected generation input model")
    snapshot = value.model_dump(  # type: ignore[attr-defined]
        mode="python",
        round_trip=True,
        warnings=False,
    )
    return model.model_validate(snapshot)


def _model_id_snapshot(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("invalid model id")
    return str(value)


def _seed_snapshot(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("invalid seed")
    return int(value)


def _prompt_snapshot(value: object) -> _PromptSnapshot:
    prompt = _revalidated_model(value, PromptRecord)
    if not prompt.prompt_id.strip() or not prompt.prompt.strip() or not prompt.language.strip():
        raise ValueError("invalid prompt")
    return _PromptSnapshot(
        prompt_id=prompt.prompt_id,
        prompt=prompt.prompt,
        language=prompt.language,
    )


def _intervention_snapshot(value: object) -> _InterventionSnapshot:
    intervention = _revalidated_model(value, InterventionRecord)
    identifiers = (
        intervention.prompt_id,
        intervention.hypothesis_id,
        intervention.intervention_id,
    )
    if any(not identifier.strip() for identifier in identifiers):
        raise ValueError("invalid intervention")
    if not intervention.counterfactual_prompt.strip():
        raise ValueError("invalid intervention")
    return _InterventionSnapshot(
        prompt_id=intervention.prompt_id,
        hypothesis_id=intervention.hypothesis_id,
        intervention_id=intervention.intervention_id,
        counterfactual_prompt=intervention.counterfactual_prompt,
    )


def _validated_grid(models: Iterable[str], seeds: Iterable[int]) -> tuple[list[str], list[int]]:
    model_values = _bounded_snapshots(
        models,
        code=ErrorCode.CONFIG,
        message="generation model axis failed validation",
        snapshot=_model_id_snapshot,
    )
    seed_values = _bounded_snapshots(
        seeds,
        code=ErrorCode.CONFIG,
        message="generation seed axis failed validation",
        snapshot=_seed_snapshot,
    )
    if not model_values:
        raise _planner_error(ErrorCode.CONFIG, "generation models must not be empty")
    if len(set(model_values)) != len(model_values):
        raise _planner_error(ErrorCode.CONFIG, "generation models must not contain duplicates")
    if not seed_values:
        raise _planner_error(ErrorCode.CONFIG, "generation seeds must not be empty")
    if len(set(seed_values)) != len(seed_values):
        raise _planner_error(ErrorCode.CONFIG, "generation seeds must not contain duplicates")
    return sorted(model_values), sorted(seed_values)


def _validated_observed_prompts(
    prompts: Iterable[PromptRecord],
) -> list[_PromptSnapshot]:
    prompt_values = _bounded_snapshots(
        prompts,
        code=ErrorCode.CONTRACT,
        message="observed prompt collection failed validation",
        snapshot=_prompt_snapshot,
    )
    if not prompt_values:
        raise _planner_error(ErrorCode.CONTRACT, "observed prompt collection must not be empty")
    prompt_ids = [prompt.prompt_id for prompt in prompt_values]
    if len(set(prompt_ids)) != len(prompt_ids):
        raise _planner_error(ErrorCode.CONTRACT, "observed prompt ids must be unique")
    return prompt_values


def _validated_interventions(
    interventions: Iterable[InterventionRecord],
) -> list[_InterventionSnapshot]:
    intervention_values = _bounded_snapshots(
        interventions,
        code=ErrorCode.CONTRACT,
        message="counterfactual intervention collection failed validation",
        snapshot=_intervention_snapshot,
    )
    if not intervention_values:
        raise _planner_error(
            ErrorCode.CONTRACT,
            "counterfactual intervention collection must not be empty",
        )
    coordinates = [
        (item.prompt_id, item.hypothesis_id, item.intervention_id) for item in intervention_values
    ]
    if len(set(coordinates)) != len(coordinates):
        raise _planner_error(
            ErrorCode.CONTRACT,
            "counterfactual intervention coordinates must be unique",
        )
    intervention_ids = [item.intervention_id for item in intervention_values]
    if len(set(intervention_ids)) != len(intervention_ids):
        raise _planner_error(ErrorCode.CONTRACT, "intervention ids must be unique")
    return intervention_values


def _prompt_mapping_entry_snapshot(
    entry: tuple[object, object],
) -> tuple[str, _PromptSnapshot]:
    key, value = entry
    if not isinstance(key, str):
        raise ValueError("invalid prompt mapping key")
    prompt = _prompt_snapshot(value)
    if key != prompt.prompt_id:
        raise ValueError("prompt mapping key mismatch")
    return key, prompt


def _validated_prompt_mapping(
    prompts_by_id: Mapping[str, PromptRecord],
) -> dict[str, _PromptSnapshot]:
    try:
        entries = prompts_by_id.items()
    except Exception:
        pass
    else:
        snapshots = _bounded_snapshots(
            entries,
            code=ErrorCode.CONTRACT,
            message="counterfactual prompt mapping failed validation",
            snapshot=_prompt_mapping_entry_snapshot,
        )
        result: dict[str, _PromptSnapshot] = {}
        for key, prompt in snapshots:
            if key in result:
                raise _planner_error(
                    ErrorCode.CONTRACT,
                    "counterfactual prompt mapping failed validation",
                )
            result[key] = prompt
        return result
    raise _planner_error(
        ErrorCode.CONTRACT,
        "counterfactual prompt mapping failed validation",
    )


def _ensure_request_capacity(*axis_sizes: int) -> None:
    request_count = 1
    for size in axis_sizes:
        request_count *= size
    if request_count > MAX_GENERATION_REQUESTS:
        raise _planner_error(
            ErrorCode.CONFIG,
            "generation request count exceeds the configured safety limit",
        )


def _parameters(value: ParameterInput) -> GenerationParameters:
    if value is None:
        return GenerationParameters()
    try:
        snapshot_source = value.values if isinstance(value, GenerationParameters) else value
        validated = GenerationParameters.model_validate({"values": snapshot_source})
    except Exception:
        pass
    else:
        return validated
    raise _planner_error(
        ErrorCode.CONTRACT,
        "generation parameters failed validation",
    )


def _endpoint_sha256(
    endpoint_type: EndpointType,
    endpoint_identity: str | None,
) -> str:
    try:
        identity = endpoint_type if endpoint_identity is None else endpoint_identity
        if type(identity) is not str or not identity:
            raise ValueError("invalid endpoint identity")
        return sha256_text(identity)
    except Exception:
        pass
    raise _planner_error(
        ErrorCode.CONFIG,
        "generation endpoint identity failed validation",
    )


def _record(
    *,
    condition: Literal["observed", "counterfactual", "confirm_arm"],
    prompt_id: str,
    prompt: str,
    language: str,
    model_id: str,
    seed_id: int,
    hypothesis_id: str | None,
    intervention_id: str | None,
    endpoint_type: EndpointType,
    endpoint_sha256: str,
    system_template_version: str,
    system_template_sha256: str,
    parameters: GenerationParameters,
    assignment_id: str | None = None,
    target_spec_id: str | None = None,
    target_instance_id: str | None = None,
    arm_protocol_id: str | None = None,
    protocol_instance_id: str | None = None,
    variant_id: str | None = None,
    arm_role: object | None = None,
) -> GenerationRequestRecord:
    prompt_sha256 = sha256_text(prompt)
    return GenerationRequestRecord(
        schema_version=GENERATION_REQUEST_SCHEMA_VERSION,
        request_id=build_generation_request_id(
            schema_version=GENERATION_REQUEST_SCHEMA_VERSION,
            condition=condition,
            prompt_id=prompt_id,
            prompt_sha256=prompt_sha256,
            language=language,
            model_id=model_id,
            seed_id=seed_id,
            hypothesis_id=hypothesis_id,
            intervention_id=intervention_id,
            endpoint_type=endpoint_type,
            endpoint_sha256=endpoint_sha256,
            system_template_version=system_template_version,
            system_template_sha256=system_template_sha256,
            parameters=parameters,
            assignment_id=assignment_id,
            target_spec_id=target_spec_id,
            target_instance_id=target_instance_id,
            arm_protocol_id=arm_protocol_id,
            protocol_instance_id=protocol_instance_id,
            variant_id=variant_id,
            arm_role=arm_role,
        ),
        condition=condition,
        prompt_id=prompt_id,
        prompt=prompt,
        prompt_sha256=prompt_sha256,
        language=language,
        model_id=model_id,
        seed_id=seed_id,
        hypothesis_id=hypothesis_id,
        intervention_id=intervention_id,
        assignment_id=assignment_id,
        target_spec_id=target_spec_id,
        target_instance_id=target_instance_id,
        arm_protocol_id=arm_protocol_id,
        protocol_instance_id=protocol_instance_id,
        variant_id=variant_id,
        arm_role=arm_role,
        endpoint_type=endpoint_type,
        endpoint_sha256=endpoint_sha256,
        system_template_version=system_template_version,
        system_template_sha256=system_template_sha256,
        parameters=parameters,
    )


def _ensure_unique_request_ids(records: list[GenerationRequestRecord]) -> None:
    request_ids = [record.request_id for record in records]
    if len(set(request_ids)) != len(request_ids):
        raise _planner_error(ErrorCode.CONTRACT, "generation request ids must be unique")


def _ensure_unique_request_coordinates(records: list[GenerationRequestRecord]) -> None:
    coordinates = [
        (
            record.condition,
            record.prompt_id,
            record.model_id,
            record.seed_id,
            record.hypothesis_id,
            record.intervention_id,
        )
        for record in records
    ]
    if len(set(coordinates)) != len(coordinates):
        raise _planner_error(ErrorCode.CONTRACT, "generation request coordinates must be unique")


def plan_observed_requests(
    prompts: Iterable[PromptRecord],
    models: Iterable[str],
    seeds: Iterable[int],
    *,
    endpoint_type: EndpointType,
    endpoint_identity: str | None = None,
    parameters: ParameterInput = None,
    system_template: str = "",
    system_template_version: str = "none",
) -> list[GenerationRequestRecord]:
    prompt_values = _validated_observed_prompts(prompts)
    model_values, seed_values = _validated_grid(models, seeds)
    _ensure_request_capacity(
        len(prompt_values),
        len(model_values),
        len(seed_values),
    )
    parameter_values = _parameters(parameters)
    endpoint_sha256 = _endpoint_sha256(endpoint_type, endpoint_identity)
    system_template_sha256 = sha256_text(system_template)
    records = [
        _record(
            condition="observed",
            prompt_id=prompt.prompt_id,
            prompt=prompt.prompt,
            language=prompt.language,
            model_id=model_id,
            seed_id=seed_id,
            hypothesis_id=None,
            intervention_id=None,
            endpoint_type=endpoint_type,
            endpoint_sha256=endpoint_sha256,
            system_template_version=system_template_version,
            system_template_sha256=system_template_sha256,
            parameters=parameter_values,
        )
        for prompt in prompt_values
        for model_id in model_values
        for seed_id in seed_values
    ]
    records.sort(
        key=lambda record: (
            record.prompt_id,
            record.model_id,
            record.seed_id,
            record.prompt_sha256,
            record.request_id,
        )
    )
    _ensure_unique_request_coordinates(records)
    _ensure_unique_request_ids(records)
    return records


def plan_counterfactual_requests(
    prompts_by_id: Mapping[str, PromptRecord],
    interventions: Iterable[InterventionRecord],
    models: Iterable[str],
    seeds: Iterable[int],
    *,
    endpoint_type: EndpointType,
    endpoint_identity: str | None = None,
    parameters: ParameterInput = None,
    system_template: str = "",
    system_template_version: str = "none",
) -> list[GenerationRequestRecord]:
    prompt_values_by_id = _validated_prompt_mapping(prompts_by_id)
    intervention_values = _validated_interventions(interventions)
    model_values, seed_values = _validated_grid(models, seeds)
    _ensure_request_capacity(
        len(intervention_values),
        len(model_values),
        len(seed_values),
    )
    parameter_values = _parameters(parameters)
    endpoint_sha256 = _endpoint_sha256(endpoint_type, endpoint_identity)
    system_template_sha256 = sha256_text(system_template)
    records: list[GenerationRequestRecord] = []
    for intervention in intervention_values:
        prompt = prompt_values_by_id.get(intervention.prompt_id)
        if prompt is None:
            raise _planner_error(
                ErrorCode.CONTRACT,
                "counterfactual intervention references an unavailable prompt",
            )
        for model_id in model_values:
            for seed_id in seed_values:
                records.append(
                    _record(
                        condition="counterfactual",
                        prompt_id=intervention.prompt_id,
                        prompt=intervention.counterfactual_prompt,
                        language=prompt.language,
                        model_id=model_id,
                        seed_id=seed_id,
                        hypothesis_id=intervention.hypothesis_id,
                        intervention_id=intervention.intervention_id,
                        endpoint_type=endpoint_type,
                        endpoint_sha256=endpoint_sha256,
                        system_template_version=system_template_version,
                        system_template_sha256=system_template_sha256,
                        parameters=parameter_values,
                    )
                )
    records.sort(
        key=lambda record: (
            record.prompt_id,
            record.hypothesis_id or "",
            record.intervention_id or "",
            record.model_id,
            record.seed_id,
            record.prompt_sha256,
            record.request_id,
        )
    )
    _ensure_unique_request_coordinates(records)
    _ensure_unique_request_ids(records)
    return records


def plan_confirmation_requests(
    assignments: Iterable[AssignmentRecord],
    variants: Iterable[PromptVariantRecord],
    config: GenerationConfig,
) -> list[GenerationRequestRecord]:
    """Join every frozen assignment to exactly one frozen prompt variant."""

    try:
        trusted_config = GenerationConfig.model_validate(config)
        assignment_values = _bounded_snapshots(
            assignments,
            code=ErrorCode.CONTRACT,
            message="confirmation assignment collection failed validation",
            snapshot=lambda value: _revalidated_model(value, AssignmentRecord),
        )
        variant_values = _bounded_snapshots(
            variants,
            code=ErrorCode.CONTRACT,
            message="confirmation variant collection failed validation",
            snapshot=lambda value: _revalidated_model(value, PromptVariantRecord),
        )
        if not assignment_values or not variant_values:
            raise ValueError
        assignment_ids = tuple(item.assignment_id for item in assignment_values)
        variant_ids = tuple(item.variant_id for item in variant_values)
        if (
            len(assignment_ids) != len(set(assignment_ids))
            or len(variant_ids) != len(set(variant_ids))
        ):
            raise ValueError
        variant_by_id = {item.variant_id: item for item in variant_values}
        referenced_variant_ids = {item.variant_id for item in assignment_values}
        if referenced_variant_ids != set(variant_by_id):
            raise ValueError

        if trusted_config.provider == "openai_compatible":
            provider = trusted_config.openai_compatible
            if provider is None:
                raise ValueError
            endpoint_type: EndpointType = "chat_completions"
            endpoint_identity = provider.base_url
            parameters = _parameters(provider.parameters)
            system_template = provider.system_template
            system_template_version = provider.system_template_version
        elif trusted_config.provider == "file":
            if not trusted_config.file_provider_dir:
                raise ValueError
            endpoint_type = "offline"
            endpoint_identity = trusted_config.file_provider_dir
            parameters = GenerationParameters()
            system_template = ""
            system_template_version = "none"
        elif trusted_config.provider == "mock":
            endpoint_type = "mock"
            endpoint_identity = "mock"
            parameters = GenerationParameters()
            system_template = ""
            system_template_version = "none"
        else:
            raise ValueError
        endpoint_sha256 = _endpoint_sha256(endpoint_type, endpoint_identity)
        system_template_sha256 = sha256_text(system_template)

        records: list[GenerationRequestRecord] = []
        for assignment in assignment_values:
            variant = variant_by_id.get(assignment.variant_id)
            unit = assignment.experimental_unit
            if (
                variant is None
                or assignment.seed_id not in trusted_config.confirmation_seeds
                or variant.task_id != unit.task_id
                or variant.hypothesis_id != unit.hypothesis_id
                or variant.target_spec_id != assignment.target_spec_id
                or variant.target_instance_id != assignment.target_instance_id
                or variant.arm_protocol_id != assignment.arm_protocol_id
                or variant.protocol_instance_id != assignment.protocol_instance_id
                or variant.arm_role is not assignment.arm_role
            ):
                raise ValueError
            records.append(
                _record(
                    condition="confirm_arm",
                    prompt_id=variant.variant_prompt_id,
                    prompt=variant.prompt_text,
                    language="python",
                    model_id=unit.model_id,
                    seed_id=assignment.seed_id,
                    hypothesis_id=unit.hypothesis_id,
                    intervention_id=None,
                    endpoint_type=endpoint_type,
                    endpoint_sha256=endpoint_sha256,
                    system_template_version=system_template_version,
                    system_template_sha256=system_template_sha256,
                    parameters=parameters,
                    assignment_id=assignment.assignment_id,
                    target_spec_id=assignment.target_spec_id,
                    target_instance_id=assignment.target_instance_id,
                    arm_protocol_id=assignment.arm_protocol_id,
                    protocol_instance_id=assignment.protocol_instance_id,
                    variant_id=assignment.variant_id,
                    arm_role=assignment.arm_role,
                )
            )
        records.sort(key=lambda item: (item.assignment_id or "", item.request_id))
        if len({item.request_id for item in records}) != len(records):
            raise ValueError
        return records
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except SecAwareError:
        raise
    except Exception:
        raise _planner_error(
            ErrorCode.CONTRACT,
            "confirmation generation planning failed validation",
        ) from None

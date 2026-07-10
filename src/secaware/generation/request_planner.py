import hashlib
from collections.abc import Iterable, Mapping
from typing import Literal

from secaware.errors import ErrorCode, JSONValue, SecAwareError
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.common import SCHEMA_VERSION
from secaware.schema.generation import GenerationParameters, GenerationRequestRecord
from secaware.schema.interventions import InterventionRecord
from secaware.schema.records import PromptRecord


EndpointType = Literal["mock", "offline", "chat_completions"]
ParameterInput = GenerationParameters | Mapping[str, JSONValue] | None


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _planner_error(code: ErrorCode, message: str) -> SecAwareError:
    return SecAwareError(code=code, stage="generation-planner", message=message)


def _validated_grid(
    models: Iterable[str], seeds: Iterable[int]
) -> tuple[list[str], list[int]]:
    model_values = list(models)
    seed_values = list(seeds)
    if not model_values:
        raise _planner_error(ErrorCode.CONFIG, "generation models must not be empty")
    if len(set(model_values)) != len(model_values):
        raise _planner_error(ErrorCode.CONFIG, "generation models must not contain duplicates")
    if not seed_values:
        raise _planner_error(ErrorCode.CONFIG, "generation seeds must not be empty")
    if len(set(seed_values)) != len(seed_values):
        raise _planner_error(ErrorCode.CONFIG, "generation seeds must not contain duplicates")
    return sorted(model_values), sorted(seed_values)


def _parameters(value: ParameterInput) -> GenerationParameters:
    if value is None:
        return GenerationParameters()
    if isinstance(value, GenerationParameters):
        return value.model_copy(deep=True)
    return GenerationParameters(values=dict(value))


def _request_id(
    *,
    condition: Literal["observed", "counterfactual"],
    prompt_id: str,
    prompt_sha256: str,
    model_id: str,
    seed_id: int,
    hypothesis_id: str | None,
    intervention_id: str | None,
    endpoint_type: EndpointType,
    system_template_version: str,
    system_template_sha256: str,
    parameters: GenerationParameters,
) -> str:
    identity = {
        "condition": condition,
        "prompt_id": prompt_id,
        "prompt_sha256": prompt_sha256,
        "model_id": model_id,
        "seed_id": seed_id,
        "hypothesis_id": hypothesis_id,
        "intervention_id": intervention_id,
        "endpoint_type": endpoint_type,
        "system_template_version": system_template_version,
        "system_template_sha256": system_template_sha256,
        "parameters": parameters.model_dump(mode="json"),
    }
    return f"req_{canonical_sha256(identity)}"


def _record(
    *,
    condition: Literal["observed", "counterfactual"],
    prompt_id: str,
    prompt: str,
    language: str,
    model_id: str,
    seed_id: int,
    hypothesis_id: str | None,
    intervention_id: str | None,
    endpoint_type: EndpointType,
    system_template_version: str,
    system_template_sha256: str,
    parameters: GenerationParameters,
) -> GenerationRequestRecord:
    prompt_sha256 = sha256_text(prompt)
    return GenerationRequestRecord(
        schema_version=SCHEMA_VERSION,
        request_id=_request_id(
            condition=condition,
            prompt_id=prompt_id,
            prompt_sha256=prompt_sha256,
            model_id=model_id,
            seed_id=seed_id,
            hypothesis_id=hypothesis_id,
            intervention_id=intervention_id,
            endpoint_type=endpoint_type,
            system_template_version=system_template_version,
            system_template_sha256=system_template_sha256,
            parameters=parameters,
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
        endpoint_type=endpoint_type,
        system_template_version=system_template_version,
        system_template_sha256=system_template_sha256,
        parameters=parameters.model_copy(deep=True),
    )


def _ensure_unique_request_ids(records: list[GenerationRequestRecord]) -> None:
    request_ids = [record.request_id for record in records]
    if len(set(request_ids)) != len(request_ids):
        raise _planner_error(ErrorCode.CONTRACT, "generation request ids must be unique")


def plan_observed_requests(
    prompts: Iterable[PromptRecord],
    models: Iterable[str],
    seeds: Iterable[int],
    *,
    endpoint_type: EndpointType,
    parameters: ParameterInput = None,
    system_template: str = "",
    system_template_version: str = "none",
) -> list[GenerationRequestRecord]:
    model_values, seed_values = _validated_grid(models, seeds)
    parameter_values = _parameters(parameters)
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
            system_template_version=system_template_version,
            system_template_sha256=system_template_sha256,
            parameters=parameter_values,
        )
        for prompt in prompts
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
    _ensure_unique_request_ids(records)
    return records


def plan_counterfactual_requests(
    prompts_by_id: Mapping[str, PromptRecord],
    interventions: Iterable[InterventionRecord],
    models: Iterable[str],
    seeds: Iterable[int],
    *,
    endpoint_type: EndpointType,
    parameters: ParameterInput = None,
    system_template: str = "",
    system_template_version: str = "none",
) -> list[GenerationRequestRecord]:
    model_values, seed_values = _validated_grid(models, seeds)
    parameter_values = _parameters(parameters)
    system_template_sha256 = sha256_text(system_template)
    records: list[GenerationRequestRecord] = []
    for intervention in interventions:
        prompt = prompts_by_id.get(intervention.prompt_id)
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
    _ensure_unique_request_ids(records)
    return records

"""Exact natural-Prompt query/runtime assembly for one v2 discovery row."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from secaware.schema.discovery_v2 import (
    DiscoveryVariableRoleV2,
    DiscoveryVariableSourceV2,
    NaturalDiscoveryTableSpecV2,
)
from secaware.schema.policy_v2 import (
    ActionableFeatureQueryResultRecord,
    ContextQueryResultRecord,
    QueryState,
)
from secaware.schema.runtime_v2 import (
    FunctionalResultRecordV2,
    GeneratedCodeRecordV2,
    GenerationRequestRecordV2,
    NaturalCausalObservationRecordV2,
    NaturalOutcomeValueV2,
    NaturalX0ValueV2,
    OracleResultRecordV2,
    RuntimeProducerChainRecordV2,
    validate_runtime_producer_chain_v2,
)

_QUERY_STATE_CODE = {
    QueryState.PRESENT: 0,
    QueryState.ABSENT: 1,
    QueryState.NOT_APPLICABLE: 2,
    QueryState.UNRESOLVED: 3,
}


@dataclass(frozen=True, slots=True)
class AssembledNaturalObservationV2:
    observation: NaturalCausalObservationRecordV2
    producer_chain: RuntimeProducerChainRecordV2


def _outcome_projection(
    code: GeneratedCodeRecordV2,
    oracle: OracleResultRecordV2,
    functional: FunctionalResultRecordV2,
) -> dict[str, int]:
    if oracle.status == "infrastructure_failure" or functional.status == "infrastructure_failure":
        raise ValueError("natural discovery outcome encountered infrastructure failure")
    if code.code_status == "terminal_no_code":
        if (
            oracle.status != "not_evaluated_no_valid_code"
            or functional.status != "not_evaluated_no_valid_code"
        ):
            raise ValueError("natural discovery no-code evidence is incoherent")
        y_c = y_e = secure = joint = 0
    elif oracle.status == "not_evaluated_no_valid_code":
        if functional.status != "not_evaluated_no_valid_code":
            raise ValueError("natural discovery invalid-code evidence is incoherent")
        y_c = y_e = secure = joint = 0
    elif oracle.status in {"secure", "insecure", "unknown"}:
        if functional.status == "not_evaluated_no_valid_code":
            raise ValueError("natural discovery functional evidence is incoherent")
        y_c = 1
        y_e = int(oracle.status in {"secure", "insecure"})
        secure = int(oracle.status == "secure")
        joint = (
            2
            if functional.status == "not_applicable"
            else secure * int(functional.status == "pass")
        )
    else:
        raise ValueError("natural discovery Oracle evidence is unsupported")
    return {
        "y_c": y_c,
        "y_e": y_e,
        "y_secure_yield": secure,
        "y_joint": joint,
    }


def assemble_natural_causal_observation_v2(
    *,
    table_spec: NaturalDiscoveryTableSpecV2,
    generation_request: GenerationRequestRecordV2,
    generated_code: GeneratedCodeRecordV2,
    oracle_result: OracleResultRecordV2,
    functional_result: FunctionalResultRecordV2,
    actionable_query_results: tuple[ActionableFeatureQueryResultRecord, ...],
    context_query_results: tuple[ContextQueryResultRecord, ...] = (),
    task_metadata_values: Mapping[str, int] | None = None,
) -> AssembledNaturalObservationV2:
    """Derive X0/Y values from authenticated sources; callers never supply table values."""

    try:
        spec = NaturalDiscoveryTableSpecV2.model_validate(table_spec, strict=True)
        request = GenerationRequestRecordV2.model_validate(generation_request, strict=True)
        code = GeneratedCodeRecordV2.model_validate(generated_code, strict=True)
        oracle = OracleResultRecordV2.model_validate(oracle_result, strict=True)
        functional = FunctionalResultRecordV2.model_validate(functional_result, strict=True)
        chain = validate_runtime_producer_chain_v2(request, code, oracle, functional)
        if request.regime_id != "natural_prompt_discovery" or request.model_id != spec.model_id:
            raise ValueError
        support = next(
            (
                item
                for item in spec.task_slot_support
                if item.task_instance_id == request.task_instance_id
            ),
            None,
        )
        if (
            support is None
            or request.semantic_task_cluster_id != support.semantic_task_cluster_id
            or request.prompt_id != support.natural_prompt_id
            or request.request_randomness_slot not in support.request_randomness_slots
            or request.provider_seed != support.seed_for_slot(request.request_randomness_slot)
        ):
            raise ValueError
        actionable = tuple(
            ActionableFeatureQueryResultRecord.model_validate(item, strict=True)
            for item in actionable_query_results
        )
        contexts = tuple(
            ContextQueryResultRecord.model_validate(item, strict=True)
            for item in context_query_results
        )
        actionable_by_source = {item.actionable_feature_spec_id: item for item in actionable}
        context_by_source = {item.context_query_id: item for item in contexts}
        if len(actionable_by_source) != len(actionable) or len(context_by_source) != len(contexts):
            raise ValueError
        metadata = {} if task_metadata_values is None else dict(task_metadata_values)
        x0: list[NaturalX0ValueV2] = []
        outcomes: list[NaturalOutcomeValueV2] = []
        projected_outcomes = _outcome_projection(code, oracle, functional)
        for variable in spec.variables:
            if variable.source_kind is DiscoveryVariableSourceV2.ACTIONABLE_QUERY:
                result = actionable_by_source.get(variable.source_id)
                if (
                    result is None
                    or result.task_instance_id != request.task_instance_id
                    or result.natural_prompt_id != request.prompt_id
                    or result.feature_catalog_sha256 != variable.source_catalog_sha256
                    or result.query_semantics_version != variable.query_semantics_version
                ):
                    raise ValueError
                x0.append(
                    NaturalX0ValueV2(
                        variable_id=variable.variable_id,
                        state=_QUERY_STATE_CODE[result.state],
                    )
                )
            elif variable.source_kind is DiscoveryVariableSourceV2.CONTEXT_QUERY:
                result = context_by_source.get(variable.source_id)
                if (
                    result is None
                    or result.task_instance_id != request.task_instance_id
                    or result.natural_prompt_id != request.prompt_id
                    or result.context_query_catalog_sha256 != variable.source_catalog_sha256
                    or result.query_semantics_version != variable.query_semantics_version
                ):
                    raise ValueError
                x0.append(
                    NaturalX0ValueV2(
                        variable_id=variable.variable_id,
                        state=_QUERY_STATE_CODE[result.state],
                    )
                )
            elif variable.source_kind is DiscoveryVariableSourceV2.TASK_METADATA:
                state = metadata.pop(variable.variable_id, None)
                if type(state) is not int or not 0 <= state < len(variable.states):
                    raise ValueError
                x0.append(NaturalX0ValueV2(variable_id=variable.variable_id, state=state))
            elif variable.source_kind is DiscoveryVariableSourceV2.OUTCOME_PROJECTION:
                outcomes.append(
                    NaturalOutcomeValueV2(
                        variable_id=variable.variable_id,
                        state=projected_outcomes[variable.source_id],
                    )
                )
            else:  # defensive against future enum expansion
                raise ValueError
        expected_actionable = {
            item.source_id
            for item in spec.variables
            if item.source_kind is DiscoveryVariableSourceV2.ACTIONABLE_QUERY
        }
        expected_context = {
            item.source_id
            for item in spec.variables
            if item.source_kind is DiscoveryVariableSourceV2.CONTEXT_QUERY
        }
        if (
            set(actionable_by_source) != expected_actionable
            or set(context_by_source) != expected_context
            or metadata
            or not x0
            or not outcomes
            or any(item.role is DiscoveryVariableRoleV2.Y for item in spec.variables[: len(x0)])
        ):
            raise ValueError
        observation = NaturalCausalObservationRecordV2.from_content(
            regime_id=request.regime_id,
            semantic_task_cluster_id=request.semantic_task_cluster_id,
            task_instance_id=request.task_instance_id,
            model_id=request.model_id,
            request_randomness_slot=request.request_randomness_slot,
            provider_seed=request.provider_seed,
            producer_chain_id=chain.producer_chain_id,
            table_id=spec.table_spec_id,
            prompt_id=request.prompt_id,
            natural_x0=tuple(sorted(x0, key=lambda item: item.variable_id)),
            outcomes=tuple(sorted(outcomes, key=lambda item: item.variable_id)),
        )
        return AssembledNaturalObservationV2(observation=observation, producer_chain=chain)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception as error:
        raise ValueError("natural discovery v2 assembly failed exact validation") from error


__all__ = ["AssembledNaturalObservationV2", "assemble_natural_causal_observation_v2"]

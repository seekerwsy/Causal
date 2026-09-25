"""Linear extraction orchestration and closed provider evidence."""

from __future__ import annotations
import hashlib
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Any
from prompt_mechanism_study.artifact_io import file_sha256, read_json, write_bundle
from prompt_mechanism_study.llm import complete_chat
from prompt_mechanism_study.tsg.source_records import ExtractionAttempt, attempt_graph
from prompt_mechanism_study.tsg.prompt_contract import (
    task_context_contract_record,
    OpenTaskContract,
)
from prompt_mechanism_study.tsg.prompt_tsg import (
    PromptTSG,
    catalog_sha256,
    load_catalog,
    prompt_tsg_record,
)
from prompt_mechanism_study.tsg.source_records import record_response_format
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.tsg.task_input import prepare_task_input
from prompt_mechanism_study.tsg.source_codec import (
    PromptContractExtractionError,
    contract_decision_request,
)
from prompt_mechanism_study.tsg.scope_assessment import (
    _inventory_status,
    assess_fixed_scope_response,
    fixed_scope_request,
    fixed_scope_response_format,
)


Provider = Callable[[dict[str, Any], Mapping[str, Any], str], bytes]


def extract_task_contract(
    task: Mapping[str, Any],
    *,
    catalog: Mapping[str, Any],
    evaluator: Mapping[str, Any],
    annotator_prompt: str,
    review_status: str,
    provider: Provider = complete_chat,
) -> tuple[OpenTaskContract, PromptTSG, dict[str, Any], bytes]:
    """Extract source semantics only; the final two values are the request/raw.

    Use extract_contract_task_file for a replayable package retaining fact,
    binding and scope requests, raw responses and partial failures.
    """

    attempt = attempt_graph(
        task,
        catalog=catalog,
        evaluator=evaluator,
        annotator_prompt=annotator_prompt,
        review_status=review_status,
        provider=provider,
    )
    if not attempt.succeeded:
        raise PromptContractExtractionError(
            attempt.error_message or attempt.error_type or "task contract extraction failed"
        )
    assert attempt.contract is not None
    assert attempt.graph is not None
    assert attempt.raw is not None
    return (
        attempt.contract,
        attempt.graph,
        attempt.request,
        attempt.raw,
    )


def _attempt_task_contract(
    task: Mapping[str, Any],
    *,
    catalog: Mapping[str, Any],
    evaluator: Mapping[str, Any],
    annotator_prompt: str,
    review_status: str,
    provider: Provider,
) -> ExtractionAttempt:
    """One path: build source semantics, then assess candidate-specific scopes."""
    graph_attempt = attempt_graph(task, catalog=catalog, evaluator=evaluator,
        annotator_prompt=annotator_prompt, review_status=review_status, provider=provider)
    return assess_candidate_scopes(graph_attempt, task=task, catalog=catalog,
        evaluator=evaluator, annotator_prompt=annotator_prompt, provider=provider)


def assess_candidate_scopes(
    graph_attempt: ExtractionAttempt, *, task: Mapping[str, Any],
    catalog: Mapping[str, Any], evaluator: Mapping[str, Any],
    annotator_prompt: str, provider: Provider,
) -> ExtractionAttempt:
    """Assess candidate states after graph construction; never edit source facts or edges.

    A scope failure retains the completed source graph. The graph-only attempt
    can be reviewed without treating candidate eligibility as extraction quality.
    """
    if not graph_attempt.succeeded:
        return graph_attempt
    task = prepare_task_input(task)
    contract, graph = graph_attempt.contract, graph_attempt.graph
    provider_calls = graph_attempt.provider_calls
    scope_assessment = None
    try:
        if isinstance(contract, OpenTaskContract):
            scope_request = fixed_scope_request(contract, prompt=task["prompt"], catalog=catalog)
            scope_format = fixed_scope_response_format(scope_request)
            scope_assessment = {
                "request": scope_request, "response_format_sha256": content_hash(scope_format),
                "provider_calls": 0, "response_text": None, "response_sha256": None,
                "status": "SOURCE_INVENTORY_INCOMPLETE" if scope_request["source_inventory_status"]["status"] == "INCOMPLETE" else "NO_SOURCE_BOUND_SCOPES", "error_type": None, "error_message": None,
            }
            if scope_request["scopes"]:
                scope_assessment.update(provider_calls=1, status="FAILED")
                provider_calls += 1
                scope_raw = provider(scope_request, {**evaluator, "response_format": scope_format}, annotator_prompt)
                scope_assessment.update(response_text=scope_raw.decode("utf-8"),
                                        response_sha256=hashlib.sha256(scope_raw).hexdigest())
                scope_assessment["assessment"] = assess_fixed_scope_response(scope_raw, request=scope_request,
                    contract=contract, prompt=task["prompt"], catalog=catalog)
                scope_assessment["status"] = "COMPLETE_WITH_UNKNOWN_PRESERVED"
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception as error:
        if scope_assessment is None:
            raise  # Invalid assessment setup is a caller error, not a model verdict.
        rejected = getattr(error, "provider_response", None)
        failure = (dict(response_envelope_text=rejected.decode("utf-8"),
                        response_envelope_sha256=hashlib.sha256(rejected).hexdigest())
                   if isinstance(rejected, bytes) else None)
        if scope_assessment is not None:
            scope_assessment.update(status="FAILED", error_type=type(error).__name__, error_message=str(error))
            if failure is not None:
                scope_assessment["provider_failure"] = failure
                failure = None
        return replace(graph_attempt, provider_calls=provider_calls, contract=contract, graph=graph,
            scope_assessment=scope_assessment, provider_failure=failure)
    return replace(graph_attempt, provider_calls=provider_calls, contract=contract, graph=graph,
                   scope_assessment=scope_assessment)


def extract_contract_task_file(
    tasks_path: Path,
    catalog_path: Path,
    evaluator_path: Path,
    annotator_prompt_path: Path,
    selection_path: Path,
    output: Path,
    *,
    review_status: str = "prospective_frozen",
    provider: Provider = complete_chat,
    max_workers: int = 1,
    reference_context: dict | None = None,
) -> dict[str, Any]:
    """Extract one frozen selection into a reviewable contract-and-graph bundle."""

    if output.exists():
        raise FileExistsError(output)
    if type(max_workers) is not int or not 1 <= max_workers <= 8:
        raise PromptContractExtractionError("task worker count must be between 1 and 8")
    tasks = _rows(read_json(tasks_path), "task file")
    by_id = {task.get("task_id"): task for task in tasks}
    if len(by_id) != len(tasks) or None in by_id:
        raise PromptContractExtractionError("task identities are invalid")
    selection = read_json(selection_path)
    if (
        not isinstance(selection, dict)
        or set(selection)
        != {"schema_version", "source_tasks_sha256", "selection_rule", "task_ids", "arms_or_outcomes_used"}
        or selection["schema_version"] != "1.0"
        or selection["source_tasks_sha256"] != file_sha256(tasks_path)
        or selection["arms_or_outcomes_used"] is not False
        or not isinstance(selection["selection_rule"], str)
        or not selection["selection_rule"].strip()
        or not isinstance(selection["task_ids"], list)
        or not selection["task_ids"]
        or len(selection["task_ids"]) != len(set(selection["task_ids"]))
        or not set(selection["task_ids"]) <= set(by_id)
    ):
        raise PromptContractExtractionError("task selection is invalid or stale")
    selected = [by_id[task_id] for task_id in selection["task_ids"]]
    catalog = load_catalog(catalog_path)
    if catalog.get("schema_version") != "2.0":
        raise PromptContractExtractionError("active extraction requires an open-graph catalog")
    selected = [prepare_task_input(task) for task in selected]
    if catalog.get("concept_policy") == "DEVELOPMENT_OPEN" and review_status != "development_exposed":
        raise PromptContractExtractionError("open concept development requires an explicit development exposure")
    evaluator = _evaluator(read_json(evaluator_path))
    annotator_prompt = annotator_prompt_path.read_text(encoding="utf-8").strip()
    if not annotator_prompt:
        raise PromptContractExtractionError("contract annotator prompt is empty")
    reference = reference_context.get("reference") if reference_context else None
    reference_binding = reference_context.get("bindings", {}) if reference_context else {}

    def extract(task: Mapping[str, Any]) -> ExtractionAttempt:
        return _attempt_task_contract(
            task,
            catalog=catalog,
            evaluator=evaluator,
            annotator_prompt=annotator_prompt,
            review_status=review_status,
            provider=provider,
        )

    if max_workers == 1:
        extracted = [extract(task) for task in selected]
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            extracted = list(executor.map(extract, selected))

    contracts: list[dict[str, Any]] = []
    graphs: list[dict[str, Any]] = []
    requests: list[dict[str, Any]] = []
    responses: list[dict[str, Any]] = []
    failed_task_units: list[dict[str, Any]] = []
    for task, attempt in zip(selected, extracted, strict=True):
        requests.append({"task_id": task["task_id"], "request": attempt.request})
        responses.append(
            {
                "task_id": task["task_id"],
                "response_format_sha256": content_hash(
                    record_response_format(attempt.request)
                ),
                "provider_calls": attempt.provider_calls,
                "status": "complete" if attempt.succeeded else "failed",
                "response_sha256": (
                    hashlib.sha256(attempt.raw).hexdigest()
                    if attempt.raw is not None else None
                ),
                "response_text": (
                    attempt.raw.decode("utf-8") if attempt.raw is not None else None
                ),
                "error_type": attempt.error_type,
                "error_message": attempt.error_message,
                **({"scope_assessment": attempt.scope_assessment} if attempt.scope_assessment is not None else {}),
                **({"binding_annotation": attempt.binding_annotation} if attempt.binding_annotation is not None else {}),
                **({"provider_failure": attempt.provider_failure} if attempt.provider_failure is not None else {}),
            }
        )
        if attempt.contract is not None and attempt.graph is not None:
            contracts.append(task_context_contract_record(attempt.contract))
            graphs.append(prompt_tsg_record(attempt.graph))
        if not attempt.succeeded:
            failed_task_units.append(
                {
                    "task_id": attempt.task_id,
                    "provider_calls": attempt.provider_calls,
                    "error_type": attempt.error_type,
                    "error_message": attempt.error_message,
                }
            )
    candidate_id = f"single-evidence:{evaluator['candidate_id']}"
    complete = not failed_task_units
    report = {
        "schema_version": "1.0",
        "status": (
            "PROMPT_CONTRACT_EXTRACTION_COMPLETE"
            if complete
            else "PROMPT_CONTRACT_EXTRACTION_FAILED"
        ),
        "protocol_id": "open_tsg_instance_contract_v3_partial_evidence",
        "annotation_policy_id": "source_records_with_separate_candidate_states",
        "model_visible_routing_labels": False,
        "input_scope": "baseline_system_message_and_user_request",
        "tasks": len(selected),
        "contracts": len(contracts),
        "graphs": len(graphs),
        "provider_calls": sum(attempt.provider_calls for attempt in extracted),
        "initial_record_calls": len(extracted),
        "record_review_and_repair_calls": sum(attempt.binding_annotation["provider_calls"]
            for attempt in extracted if attempt.binding_annotation is not None),
        "graph_annotation_calls": len(extracted) + sum(attempt.binding_annotation["provider_calls"]
            for attempt in extracted if attempt.binding_annotation is not None),
        "candidate_assessment_failed_task_ids": [a.contract.task_id for a in extracted
            if a.scope_assessment and a.scope_assessment["status"] == "FAILED"],
        "fixed_scope_assessment_calls": sum(attempt.scope_assessment["provider_calls"]
            for attempt in extracted if attempt.scope_assessment is not None),
        "source_inventory_incomplete_task_units": sum(
            _inventory_status(attempt.contract)["status"] == "INCOMPLETE"
            for attempt in extracted if isinstance(attempt.contract, OpenTaskContract)),
        "withheld_scope_count": sum(len(attempt.scope_assessment["request"]["withheld_scopes"])
            for attempt in extracted if attempt.scope_assessment is not None),
        "task_workers": max_workers,
        "effective_task_workers": min(max_workers, len(selected)),
        "candidate_id": candidate_id,
        "task_file_sha256": file_sha256(tasks_path),
        "task_selection_sha256": file_sha256(selection_path),
        "catalog_sha256": catalog_sha256(catalog),
        "evaluator_sha256": file_sha256(evaluator_path),
        "annotator_prompt_sha256": file_sha256(annotator_prompt_path),
        "extractor_implementation_sha256": file_sha256(Path(__file__)),
        "provider_adapter_sha256": file_sha256(Path(provider.__code__.co_filename)),
        "response_protocol_id": "source_covered_layered_bindings_expression_v1",
        "unresolved_task_units": sum(bool(graph["unresolved_semantics"]) or bool(contract.get("unresolved_notes"))
                                     for graph, contract in zip(graphs, contracts, strict=True)),
        "failed_task_unit_count": len(failed_task_units),
        "failed_task_units": failed_task_units,
        "review_status": review_status,
        "arms_or_outcomes_used": False,
        "scientific_claim_allowed": False,
        **reference_binding,
    }
    if "response_format_sha256" in evaluator:
        report["evaluator_response_format_sha256"] = evaluator["response_format_sha256"]
    write_bundle(
        output,
        {
            "report.json": report,
            "contracts.json": contracts,
            "factor-states.json": [attempt.scope_assessment['assessment'] for attempt in extracted
                if attempt.scope_assessment and 'assessment' in attempt.scope_assessment],
            "requests.json": requests,
            "responses.json": responses,
            **({"qualification-reference.json": reference, "selection.json": selection}
               if reference is not None else {}),
            "tasks.json": selected,

        },
    )
    if not complete:
        raise PromptContractExtractionError(
            "prompt contract extraction failed; inspect closed bundle"
        )
    return report


def _evaluator(value: Any) -> dict[str, Any]:
    base_fields = {
        "schema_version",
        "candidate_id",
        "provider",
        "model_id",
        "base_url",
        "api_key_env",
        "temperature",
        "top_p",
        "seed",
        "enable_thinking",
        "timeout_seconds",
        "max_response_bytes",
        "max_attempts",
    }
    optional_fields = {"maximum_output_tokens", "maximum_input_bytes", "maximum_completion_tokens", "thinking_budget", "chat_template_kwargs"}
    present_fields = set(value) if isinstance(value, dict) else set()
    if (
        not isinstance(value, dict)
        or not base_fields <= present_fields
        or present_fields - base_fields - optional_fields
        or value["schema_version"] != "1.0"
        or value["provider"] not in {"ali_bailian_pay_as_you_go", "deepseek", "local_vllm"}
        or any(not isinstance(value[key], str) or not value[key].strip()
               for key in ("candidate_id", "model_id", "base_url"))
        or (value["api_key_env"] is not None and not isinstance(value["api_key_env"], str))
        or (value["provider"] != "local_vllm" and not value["api_key_env"])
        or type(value["temperature"]) not in (int, float) or not 0 <= value["temperature"] <= 2
        or type(value["top_p"]) not in (int, float) or not 0 < value["top_p"] <= 1
        or type(value["seed"]) is not int or type(value["enable_thinking"]) is not bool
        or type(value["timeout_seconds"]) not in (int, float) or not 0 < value["timeout_seconds"] <= 3600
        or type(value["max_response_bytes"]) is not int or value["max_response_bytes"] <= 0
        or ("chat_template_kwargs" in value and not isinstance(value["chat_template_kwargs"], dict))
        or value["max_attempts"] != 1
        or any(key in value and (type(value[key]) is not int or value[key] <= 0)
               for key in optional_fields - {"chat_template_kwargs"})
    ):
        raise PromptContractExtractionError("contract evaluator is invalid")
    return value


def _rows(value: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or any(not isinstance(row, dict) for row in value):
        raise PromptContractExtractionError(f"{label} must be a non-empty object list")
    return value


__all__ = [
    "PromptContractExtractionError",
    "contract_decision_request",
    "extract_contract_task_file",
    "extract_task_contract",
    "assess_candidate_scopes",
    "fixed_scope_request",
    "fixed_scope_response_format",
    "assess_fixed_scope_response",
]

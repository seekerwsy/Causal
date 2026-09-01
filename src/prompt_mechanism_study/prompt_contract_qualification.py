"""Independent closure and scoring for the active task-contract Gate C."""

from __future__ import annotations

import hashlib
from collections import Counter
from pathlib import Path
from typing import Any

from prompt_mechanism_study.artifact_io import (
    bundle_digest,
    read_json,
    verify_bundle,
    write_bundle,
)
from prompt_mechanism_study.mechanisms import load_mechanism_registry, tsg_mechanism_binding
from prompt_mechanism_study.prompt_contract import (
    compile_task_context_contract,
    task_context_contract_from_record,
    task_context_contract_record,
)
from prompt_mechanism_study.prompt_contract_extract import (
    consensus_contract,
    contract_decision_request,
    contract_from_response,
    contract_response_format,
)
from prompt_mechanism_study.prompt_tsg import load_catalog, prompt_tsg_record
from prompt_mechanism_study.records import canonical_json, content_hash


class PromptContractQualificationError(RuntimeError):
    """The Gate C inputs or deterministic replay closure are invalid."""

def qualify_prompt_contract_extractor(
    repository_root: Path,
    tasks_path: Path,
    extraction_bundle: Path,
    catalog_path: Path,
    registry_path: Path,
    gold_path: Path,
    proposer_evaluator_path: Path,
    proposer_prompt_path: Path,
    reviewer_evaluator_path: Path,
    reviewer_prompt_path: Path,
    output: Path,
) -> dict[str, Any]:
    """Independently close and score the task-level dual-annotation Gate C bundle."""

    root = repository_root.resolve()
    verify_bundle(extraction_bundle)
    bundle_report = read_json(extraction_bundle / "report.json")
    contracts = _rows(read_json(extraction_bundle / "contracts.json"))
    graph_rows = _rows(read_json(extraction_bundle / "graphs.json"))
    requests = _rows(read_json(extraction_bundle / "requests.json"))
    responses = _rows(read_json(extraction_bundle / "responses.json"))
    tasks = _rows(read_json(tasks_path))
    task_by_id = {row.get("task_id"): row for row in tasks}
    if len(task_by_id) != len(tasks) or None in task_by_id:
        raise PromptContractQualificationError("Prompt contract qualification task identities are invalid")

    gold = read_json(gold_path)
    required_gold = {
        "schema_version",
        "contract_protocol_id",
        "extractor_candidate_id",
        "selection_path",
        "review_completed_before_extraction",
        "arms_or_outcomes_used",
        "qualification_rule",
        "cases",
    }
    allowed_gold = {frozenset(required_gold), frozenset(required_gold | {"execution"})}
    if (
        not isinstance(gold, dict)
        or frozenset(gold) not in allowed_gold
        or gold["schema_version"] != "2.0"
        or gold["contract_protocol_id"]
        != "task_context_contract_v2_dual_blind_consensus"
        or gold["review_completed_before_extraction"] is not True
        or gold["arms_or_outcomes_used"] is not False
    ):
        raise PromptContractQualificationError("Prompt contract qualification gold record is invalid")
    execution = gold.get("execution", {"task_workers": 1})
    if (
        not isinstance(execution, dict)
        or set(execution) != {"task_workers"}
        or type(execution["task_workers"]) is not int
        or not 1 <= execution["task_workers"] <= 8
    ):
        raise PromptContractQualificationError("Prompt contract execution policy is invalid")
    rule = gold["qualification_rule"]
    if (
        not isinstance(rule, dict)
        or set(rule)
        != {
            "minimum_exact_context_accuracy",
            "minimum_present_recall",
            "maximum_false_positive_present",
            "maximum_wrong_realization",
        }
        or type(rule["minimum_exact_context_accuracy"]) is not float
        or not 0 < rule["minimum_exact_context_accuracy"] <= 1
        or type(rule["minimum_present_recall"]) is not float
        or not 0 < rule["minimum_present_recall"] <= 1
        or type(rule["maximum_false_positive_present"]) is not int
        or rule["maximum_false_positive_present"] < 0
        or type(rule["maximum_wrong_realization"]) is not int
        or rule["maximum_wrong_realization"] < 0
    ):
        raise PromptContractQualificationError("Prompt contract qualification rule is invalid")

    selection_path = (root / gold["selection_path"]).resolve()
    try:
        selection_path.relative_to(root)
    except ValueError:
        raise PromptContractQualificationError("Prompt contract qualification selection escapes repository") from None
    selection = read_json(selection_path)
    cases = _rows(gold["cases"])
    case_ids = [case.get("task_id") for case in cases]
    proposer_evaluator = read_json(proposer_evaluator_path)
    reviewer_evaluator = read_json(reviewer_evaluator_path)
    if not isinstance(proposer_evaluator, dict) or not isinstance(reviewer_evaluator, dict):
        raise PromptContractQualificationError("Prompt contract evaluator records are invalid")
    proposer_id = proposer_evaluator.get("candidate_id")
    reviewer_id = reviewer_evaluator.get("candidate_id")
    candidate_id = f"dual-blind-consensus:{proposer_id}+{reviewer_id}"
    expected_report = {
        "status": "PROMPT_CONTRACT_EXTRACTION_COMPLETE",
        "protocol_id": gold["contract_protocol_id"],
        "tasks": len(cases),
        "contracts": len(cases),
        "graphs": len(cases),
        "provider_calls": 2 * len(cases),
        "task_workers": execution["task_workers"],
        "effective_task_workers": min(execution["task_workers"], len(cases)),
        "candidate_id": candidate_id,
        "task_file_sha256": _sha256(tasks_path),
        "task_selection_sha256": _sha256(selection_path),
        "proposer_evaluator_sha256": _sha256(proposer_evaluator_path),
        "proposer_prompt_sha256": _sha256(proposer_prompt_path),
        "reviewer_evaluator_sha256": _sha256(reviewer_evaluator_path),
        "reviewer_prompt_sha256": _sha256(reviewer_prompt_path),
        "response_protocol_id": "task_keyed_prompt_contract_json_schema_v2",
        "failed_task_unit_count": 0,
        "failed_task_units": [],
        "review_status": "prospective_frozen",
        "arms_or_outcomes_used": False,
        "scientific_claim_allowed": False,
    }
    if (
        gold["extractor_candidate_id"] != candidate_id
        or case_ids != selection.get("task_ids")
        or selection.get("source_tasks_sha256") != _sha256(tasks_path)
        or any(bundle_report.get(key) != value for key, value in expected_report.items())
        or not all(
            len(rows) == len(cases)
            for rows in (contracts, graph_rows, requests, responses)
        )
    ):
        raise PromptContractQualificationError("Prompt contract qualification inputs do not close")

    catalog = load_catalog(catalog_path)
    registry = load_mechanism_registry(registry_path)
    if bundle_report.get("catalog_sha256") != hashlib.sha256(
        canonical_json(catalog).encode("utf-8")
    ).hexdigest():
        raise PromptContractQualificationError("Prompt contract catalog identity drifted")
    contract_by_task = {
        row.get("task_id"): row for row in contracts if isinstance(row.get("task_id"), str)
    }
    graph_by_task = {
        row.get("task_id"): row for row in graph_rows if isinstance(row.get("task_id"), str)
    }
    request_by_task = {
        row.get("task_id"): row for row in requests if isinstance(row.get("task_id"), str)
    }
    response_by_task = {
        row.get("task_id"): row for row in responses if isinstance(row.get("task_id"), str)
    }
    populations = (contract_by_task, graph_by_task, request_by_task, response_by_task)
    if any(set(rows) != set(case_ids) for rows in populations):
        raise PromptContractQualificationError("Prompt contract bundle population differs from gold")

    results = []
    semantic_disagreements = 0
    relation_disagreements = 0
    for case in cases:
        if set(case) != {
            "task_id",
            "expected_context",
            "expected_realization_id",
            "rationale",
        } or case["expected_context"] not in {
            "present",
            "absent",
            "unresolved",
            "absent_or_unresolved",
        }:
            raise PromptContractQualificationError("Prompt contract qualification case is invalid")
        task = task_by_id.get(case["task_id"])
        if task is None:
            raise PromptContractQualificationError("Prompt contract qualification task is missing")
        response = response_by_task[case["task_id"]]
        response_fields = {
            "task_id",
            "response_format_sha256",
            "provider_calls",
            "status",
            "proposer_response_sha256",
            "proposer_response_text",
            "reviewer_response_sha256",
            "reviewer_response_text",
            "error_type",
            "error_message",
        }
        if (
            set(response) != response_fields
            or response["provider_calls"] != 2
            or response["status"] != "complete"
            or response["error_type"] is not None
            or response["error_message"] is not None
            or not isinstance(response["proposer_response_text"], str)
            or not isinstance(response["reviewer_response_text"], str)
        ):
            raise PromptContractQualificationError("Prompt contract response closure fields are invalid")
        expected_request = contract_decision_request(task, catalog)
        if response["response_format_sha256"] != content_hash(
            contract_response_format(expected_request)
        ):
            raise PromptContractQualificationError("Prompt contract response format identity is invalid")
        proposer_raw = response["proposer_response_text"].encode("utf-8")
        reviewer_raw = response["reviewer_response_text"].encode("utf-8")
        if (
            hashlib.sha256(proposer_raw).hexdigest()
            != response["proposer_response_sha256"]
            or hashlib.sha256(reviewer_raw).hexdigest()
            != response["reviewer_response_sha256"]
        ):
            raise PromptContractQualificationError("Prompt contract response identity is invalid")
        try:
            proposer = contract_from_response(
                proposer_raw,
                task=task,
                catalog=catalog,
                annotator_id=proposer_id,
                review_status="prospective_frozen",
            )
            reviewer = contract_from_response(
                reviewer_raw,
                task=task,
                catalog=catalog,
                annotator_id=reviewer_id,
                review_status="prospective_frozen",
            )
            expected_contract = consensus_contract(
                proposer, reviewer, annotator_id=candidate_id
            )
            contract = task_context_contract_from_record(
                contract_by_task[case["task_id"]]
            )
            if task_context_contract_record(expected_contract) != task_context_contract_record(
                contract
            ):
                raise PromptContractQualificationError("Prompt contract consensus replay differs")
            graph = compile_task_context_contract(
                contract, prompt=task["prompt"], catalog=catalog
            )
        except PromptTSGError as error:
            raise PromptContractQualificationError(str(error)) from None
        if (
            request_by_task[case["task_id"]] != expected_request
            or prompt_tsg_record(graph) != graph_by_task[case["task_id"]]
            or contract.annotator_id != candidate_id
            or contract.review_status != "prospective_frozen"
        ):
            raise PromptContractQualificationError("Prompt contract deterministic replay differs")
        semantic_disagreements += sum(
            (
                left.state,
                left.evidence_text,
                left.occurrence,
                left.attributes,
            )
            != (
                right.state,
                right.evidence_text,
                right.occurrence,
                right.attributes,
            )
            for left, right in zip(
                proposer.semantic_decisions, reviewer.semantic_decisions, strict=True
            )
        )
        relation_disagreements += sum(
            left.state is not right.state
            for left, right in zip(
                proposer.relation_decisions, reviewer.relation_decisions, strict=True
            )
        )
        binding = tsg_mechanism_binding(task, graph, catalog, registry)
        actual_context = (
            "present"
            if binding["realization_id"] is not None
            else "unresolved"
            if binding["decision"] == "unresolved"
            else "absent"
        )
        context_matched = actual_context == case["expected_context"] or (
            case["expected_context"] == "absent_or_unresolved"
            and actual_context in {"absent", "unresolved"}
        )
        matched = context_matched and (
            binding["realization_id"] == case["expected_realization_id"]
        )
        results.append(
            {
                "task_id": case["task_id"],
                "expected_context": case["expected_context"],
                "actual_context": actual_context,
                "expected_realization_id": case["expected_realization_id"],
                "actual_realization_id": binding["realization_id"],
                "binding_decision": binding["decision"],
                "matched": matched,
            }
        )

    mismatches = [row for row in results if not row["matched"]]
    expected_present = [row for row in results if row["expected_context"] == "present"]
    if not expected_present:
        raise PromptContractQualificationError("Prompt contract qualification lacks positive gold")
    present_recovered = [
        row
        for row in expected_present
        if row["actual_context"] == "present"
        and row["actual_realization_id"] == row["expected_realization_id"]
    ]
    false_positive_present = [
        row
        for row in results
        if row["expected_context"] != "present" and row["actual_context"] == "present"
    ]
    wrong_realization = [
        row
        for row in results
        if row["actual_realization_id"] is not None
        and row["actual_realization_id"] != row["expected_realization_id"]
    ]
    exact_accuracy = (len(results) - len(mismatches)) / len(results)
    present_recall = len(present_recovered) / len(expected_present)
    qualified = (
        exact_accuracy >= rule["minimum_exact_context_accuracy"]
        and present_recall >= rule["minimum_present_recall"]
        and len(false_positive_present) <= rule["maximum_false_positive_present"]
        and len(wrong_realization) <= rule["maximum_wrong_realization"]
    )
    positive_gold_realization_ids = sorted(
        {
            row["expected_realization_id"]
            for row in cases
            if row["expected_context"] == "present"
        }
    )
    catalog_realization_ids = sorted(
        {query["realization_id"] for query in catalog["queries"]}
    )
    report = {
        "schema_version": "2.0",
        "status": "QUALIFIED_FOR_FORMAL_EXTRACTION" if qualified else "QUALIFICATION_FAILED",
        "contract_protocol_id": gold["contract_protocol_id"],
        "extractor_candidate_id": candidate_id,
        "holdout_task_units": len(cases),
        "matched_task_units": len(cases) - len(mismatches),
        "mismatched_task_units": len(mismatches),
        "exact_context_accuracy": round(exact_accuracy, 6),
        "present_recall": round(present_recall, 6),
        "false_positive_present": len(false_positive_present),
        "wrong_realization": len(wrong_realization),
        "semantic_annotation_disagreements": semantic_disagreements,
        "relation_annotation_disagreements": relation_disagreements,
        "qualification_rule": rule,
        "positive_gold_realization_ids": positive_gold_realization_ids,
        "catalog_realization_ids_without_positive_gold": sorted(
            set(catalog_realization_ids) - set(positive_gold_realization_ids)
        ),
        "context_counts": dict(
            sorted(Counter(row["expected_context"] for row in cases).items())
        ),
        "extractor_bundle_sha256": bundle_digest(extraction_bundle),
        "extractor_implementation_sha256": bundle_report[
            "extractor_implementation_sha256"
        ],
        "catalog_sha256": _sha256(catalog_path),
        "registry_sha256": _sha256(registry_path),
        "gold_sha256": _sha256(gold_path),
        "selection_sha256": _sha256(selection_path),
        "arms_or_outcomes_used": False,
        "scientific_claim_allowed": False,
        "claim_boundary": (
            "Gate C qualifies task-context selection only for expected-present realizations "
            "represented in this frozen source-only holdout; it is not effect evidence."
        ),
    }
    write_bundle(output, {"case-results.json": results, "qualification.json": report})
    return report



def _rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(row, dict) for row in value):
        raise PromptContractQualificationError("qualification input must contain object rows")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


__all__ = [
    "PromptContractQualificationError",
    "qualify_prompt_contract_extractor",
]

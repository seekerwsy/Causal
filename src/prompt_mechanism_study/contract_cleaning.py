"""Outcome-blind content cleaning for the reviewer task-unit data foundation."""

from __future__ import annotations

import hashlib
import json
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from prompt_mechanism_study.artifact_io import (
    bundle_digest,
    read_json,
    verify_bundle,
    write_bundle,
)
from prompt_mechanism_study.curation import (
    CurationError,
    _batches,
    _execute,
    _initialize,
)
from prompt_mechanism_study.functional_judge import JudgeGateError, bailian_complete
from prompt_mechanism_study.records import (
    canonical_json,
    content_hash,
    content_id,
)
from prompt_mechanism_study.task_unit_data import (
    _canonical_jsonl,
    _readiness_action,
    _unique_by,
    verify_task_unit_data,
)


Provider = Callable[[dict[str, Any], Mapping[str, Any], str], bytes]
_BATCH_ITEMS = 5
_CONTENT_FIELDS = (
    "requirements",
    "inputs",
    "outputs",
    "side_effects",
    "environment_dependencies",
)
_SOURCE_ASSESSMENTS = {"sufficient", "insufficient", "defect", "uncertain"}
_REPAIR_CATEGORIES = {
    "EVIDENCE_BACKFILL_ONLY",
    "CONTRACT_EXTRACTION_ERROR",
    "OMITTED_EXPLICIT_REQUIREMENT",
    "UNSUPPORTED_ADDITION",
    "SCOPE_OR_CONDITION_ERROR",
    "SOURCE_SPECIFICATION_INSUFFICIENT",
    "SOURCE_DEFECT",
    "INDEPENDENT_ADJUDICATION_REQUIRED",
}
_REVIEW_ISSUES = {
    "none",
    "unsupported_requirement",
    "missing_explicit_requirement",
    "entrypoint_mismatch",
    "input_mismatch",
    "output_mismatch",
    "side_effect_mismatch",
    "dependency_mismatch",
    "evidence_mismatch",
    "prompt_not_software_task",
    "external_context_missing",
    "ambiguous_interface",
    "uncertain_semantics",
    "other",
}
_FINAL_JSONL_FILES = {
    "contract-repair-ledger.jsonl",
    "functional-contracts.jsonl",
    "near-duplicate-groups.jsonl",
    "readiness-worklist.jsonl",
    "source-lineages.jsonl",
    "task-quality.jsonl",
    "task-roles.jsonl",
    "task-units.jsonl",
}
_FINAL_FILES = _FINAL_JSONL_FILES | {"report.json"}
_TERMINAL_QUALITY = {
    "QUALITY_INCLUDED",
    "QUALITY_EXCLUDED_SOURCE_DEFECT",
    "QUALITY_EXCLUDED_INSUFFICIENT_SPECIFICATION",
}


class ContractCleaningError(RuntimeError):
    """The frozen cleaning input, model response, or final decision is invalid."""


def freeze_future_evaluation_reservation(
    base_bundle: Path, output: Path, *, producer_commit: str
) -> dict[str, Any]:
    """Reserve one unexposed task per clean near-duplicate group without reading prompts."""

    base = base_bundle.resolve()
    verify_task_unit_data(base)
    roles = _unique_by(
        _canonical_jsonl(base / "task-roles.jsonl", "roles"), "task_unit_id", "roles"
    )
    groups = _canonical_jsonl(base / "near-duplicate-groups.jsonl", "near-duplicate groups")
    reservations = []
    contaminated_groups = 0
    for group in sorted(groups, key=lambda row: row["near_duplicate_group_id"]):
        task_ids = group["task_unit_ids"]
        if any(roles[task_id]["data_role"] != "UNASSIGNED" for task_id in task_ids):
            contaminated_groups += 1
            continue
        selected = min(task_ids)
        core = {
            "schema_version": "future-evaluation-reservation-1.0",
            "task_unit_id": selected,
            "near_duplicate_group_id": group["near_duplicate_group_id"],
            "reservation_status": "SEALED_CURATION_ONLY_PENDING_FORMAL_ALLOCATION",
            "selection_rule": "minimum_task_unit_id_per_fully_unexposed_near_duplicate_group_v1",
            "prospective_formal_role_assigned": False,
            "arms_or_outcomes_used": False,
        }
        reservations.append(
            {**core, "future_evaluation_reservation_record_sha256": content_hash(core)}
        )
    report = {
        "schema_version": "1.0",
        "status": "FUTURE_EVALUATION_RESERVATION_FROZEN",
        "base_bundle_sha256": _manifest_digest(base),
        "reserved_task_unit_count": len(reservations),
        "excluded_exposed_or_mixed_group_count": contaminated_groups,
        "selection_uses_prompt_content": False,
        "selection_uses_quality_or_readiness": False,
        "selection_uses_arms_or_outcomes": False,
        "producer_commit": producer_commit,
        "formal_role_assignment_frozen": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(
        output.resolve(),
        {"reservations.json": reservations, "report.json": report},
    )
    return report


def run_contract_content_proposals(
    repository_root: Path,
    base_bundle: Path,
    output: Path,
    *,
    producer_commit: str,
    max_new_batches: int | None = None,
    workers: int = 1,
    stop_after_evidence: bool = False,
    provider: Provider = bailian_complete,
) -> dict[str, Any]:
    """Backfill faithful contracts and repair only contracts already judged faulty."""

    if not producer_commit or any(character.isspace() for character in producer_commit):
        raise ValueError("producer_commit must be one non-empty token")
    base = base_bundle.resolve()
    verify_task_unit_data(base)
    tasks, contracts, quality = _base_population(base)
    items = []
    for task_id in sorted(tasks):
        task = tasks[task_id]
        contract = contracts[task_id]
        quality_row = quality[task_id]
        common = {
            "task_unit_id": task_id,
            "language": task["declared_execution_context"]["language"],
            "source_prompt": task["model_visible_input"]["natural_prompt"],
            "source_prompt_sha256": task["model_visible_input"][
                "natural_prompt_content_sha256"
            ],
            "old_contract": _contract_payload(contract),
            "old_contract_id": contract["contract_id"],
            "old_review": contract["review"],
            "old_quality_disposition": quality_row["quality_disposition"],
        }
        common["mode"] = (
            "EVIDENCE_BACKFILL_ONLY"
            if contract["review"]["contract_status"] == "faithful"
            else "SEMANTIC_REPAIR"
        )
        items.append(common)

    evidence_items = [item for item in items if item["mode"] == "EVIDENCE_BACKFILL_ONLY"]
    initial_repair_items = [item for item in items if item["mode"] == "SEMANTIC_REPAIR"]
    root = output.resolve()
    root.mkdir(parents=True, exist_ok=True)
    base_identity = {
        "schema_version": "1.0",
        "base_bundle_sha256": _manifest_digest(base),
        "task_unit_count": len(items),
        "producer_commit": producer_commit,
        "arms_or_outcomes_used": False,
        "formal_roles_used": False,
    }
    evidence_results, evidence_complete, evidence_plan = _run_stage(
        repository_root,
        root / "evidence",
        evidence_items,
        prompt_name="contract-evidence-backfill-v1.txt",
        config_name="contract-cleaning-producer-qwen35flash.json",
        stage="contract_evidence_backfill",
        base_identity=base_identity,
        request_builder=_evidence_request,
        parser=_parse_evidence_backfill,
        max_new_batches=max_new_batches,
        workers=workers,
        provider=provider,
    )
    if not evidence_complete:
        return _proposal_progress(
            len(items), len(evidence_items), len(initial_repair_items), evidence_results, [], False
        )

    evidence_by_task = _unique_results(evidence_results, "evidence backfill")
    escalated_ids = {
        task_id
        for task_id, row in evidence_by_task.items()
        if row["binding_status"] == "needs_repair"
    }
    if stop_after_evidence:
        return {
            "schema_version": "1.0",
            "status": "CONTRACT_EVIDENCE_BACKFILL_COMPLETE",
            "task_unit_count": len(items),
            "evidence_item_count": len(evidence_items),
            "evidence_bound_count": len(evidence_items) - len(escalated_ids),
            "evidence_escalation_count": len(escalated_ids),
            "initial_semantic_repair_count": len(initial_repair_items),
            "complete": False,
        }
    repair_items = sorted(
        initial_repair_items
        + [item for item in evidence_items if item["task_unit_id"] in escalated_ids],
        key=lambda item: item["task_unit_id"],
    )
    repair_results, repair_complete, repair_plan = _run_stage(
        repository_root,
        root / "repair",
        repair_items,
        prompt_name="contract-semantic-repair-v2.txt",
        config_name="contract-cleaning-producer-qwen35flash.json",
        stage="contract_semantic_repair",
        base_identity={**base_identity, "evidence_plan_sha256": content_hash(evidence_plan)},
        request_builder=_repair_request,
        parser=_parse_semantic_repairs,
        max_new_batches=max_new_batches,
        workers=workers,
        provider=provider,
    )
    if not repair_complete:
        return _proposal_progress(
            len(items),
            len(evidence_items),
            len(repair_items),
            evidence_results,
            repair_results,
            False,
        )

    final = root / "final"
    if final.exists():
        verify_bundle(final)
        return read_json(final / "report.json")
    repair_by_task = _unique_results(repair_results, "semantic repairs")
    proposed = []
    ledger = []
    for item in items:
        task_id = item["task_unit_id"]
        evidence_row = evidence_by_task.get(task_id)
        if evidence_row is not None and evidence_row["binding_status"] == "bound":
            proposal_mode = "EVIDENCE_BACKFILL_ONLY"
            contract_values = item["old_contract"]
            evidence = evidence_row["content_evidence"]
            source_assessment = "sufficient"
            category = "EVIDENCE_BACKFILL_ONLY"
            reason = evidence_row["reason"]
        else:
            repair = repair_by_task[task_id]
            proposal_mode = "SEMANTIC_REPAIR"
            contract_values = {key: repair[key] for key in ("resolution_status", "entrypoint", *_CONTENT_FIELDS)}
            evidence = repair["content_evidence"]
            source_assessment = repair["source_specification_assessment"]
            category = repair["repair_category"]
            reason = repair["reason"]
        contract_core = {
            "schema_version": "functional-contract-cleaning-proposal-1.0",
            "task_unit_id": task_id,
            "record_id": tasks[task_id]["representative_record_id"],
            "source_prompt_sha256": item["source_prompt_sha256"],
            **contract_values,
            "content_evidence": evidence,
            "proposal_mode": proposal_mode,
            "producer_source_assessment": source_assessment,
            "producer_reason": reason,
            "arms_or_outcomes_used": False,
        }
        contract_id = content_id("functional_contract_", contract_core)
        proposal = {**contract_core, "contract_id": contract_id}
        proposed.append(proposal)
        ledger_core = {
            "schema_version": "contract-repair-ledger-1.0",
            "task_unit_id": task_id,
            "old_contract_id": item["old_contract_id"],
            "repair_category": category,
            "repair_status": "PROPOSED_PENDING_INDEPENDENT_REVIEW",
            "new_contract_id": contract_id,
            "source_specification_disposition": source_assessment,
            "evidence_span_count": _evidence_span_count(evidence),
            "review_status": "PENDING",
            "review_issue_codes": [],
            "input_sha256": content_hash(
                {
                    "task_unit_id": task_id,
                    "source_prompt_sha256": item["source_prompt_sha256"],
                    "old_contract_id": item["old_contract_id"],
                }
            ),
            "output_sha256": content_hash(proposal),
            "producer_commit": producer_commit,
        }
        ledger.append({**ledger_core, "repair_ledger_record_sha256": content_hash(ledger_core)})
    report = {
        "schema_version": "1.0",
        "status": "CONTRACT_CONTENT_PROPOSALS_FROZEN",
        "base_bundle_sha256": _manifest_digest(base),
        "task_unit_count": len(items),
        "evidence_only_count": sum(row["proposal_mode"] == "EVIDENCE_BACKFILL_ONLY" for row in proposed),
        "semantic_repair_count": sum(row["proposal_mode"] == "SEMANTIC_REPAIR" for row in proposed),
        "evidence_escalation_count": len(escalated_ids),
        "producer_source_assessment_counts": dict(
            sorted(Counter(row["producer_source_assessment"] for row in proposed).items())
        ),
        "producer_commit": producer_commit,
        "evidence_plan_sha256": content_hash(evidence_plan),
        "repair_plan_sha256": content_hash(repair_plan),
        "all_task_units_accounted_for": len(proposed) == len(items),
        "arms_or_outcomes_used": False,
        "formal_roles_used": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(
        final,
        {
            "proposed-contracts.json": proposed,
            "contract-repair-ledger.json": ledger,
            "report.json": report,
        },
    )
    return report


def run_contract_content_review(
    repository_root: Path,
    base_bundle: Path,
    proposals_root: Path,
    output: Path,
    *,
    max_new_batches: int | None = None,
    workers: int = 1,
    provider: Provider = bailian_complete,
) -> dict[str, Any]:
    """Blindly review every proposed contract and preserve nonterminal failures."""

    base = base_bundle.resolve()
    proposals = proposals_root.resolve()
    verify_task_unit_data(base)
    verify_bundle(proposals)
    tasks, _, _ = _base_population(base)
    rows = _unique_by(
        read_json(proposals / "proposed-contracts.json"), "task_unit_id", "proposed contracts"
    )
    if set(rows) != set(tasks):
        raise ContractCleaningError("proposal population differs from the base task population")
    items = [
        {
            "task_unit_id": task_id,
            "language": tasks[task_id]["declared_execution_context"]["language"],
            "source_prompt": tasks[task_id]["model_visible_input"]["natural_prompt"],
            "contract": _proposal_payload(rows[task_id]),
        }
        for task_id in sorted(tasks)
    ]
    results, complete, plan = _run_stage(
        repository_root,
        output.resolve(),
        items,
        prompt_name="contract-content-review-v1.txt",
        config_name="contract-cleaning-reviewer-qwen37max.json",
        stage="contract_content_independent_review",
        base_identity={
            "schema_version": "1.0",
            "base_bundle_sha256": _manifest_digest(base),
            "proposals_bundle_sha256": bundle_digest(proposals),
            "task_unit_count": len(items),
            "arms_or_outcomes_used": False,
            "formal_roles_used": False,
        },
        request_builder=_review_request,
        parser=_parse_content_reviews,
        max_new_batches=max_new_batches,
        workers=workers,
        provider=provider,
    )
    if not complete:
        return {
            "schema_version": "1.0",
            "status": "CONTRACT_CONTENT_REVIEW_IN_PROGRESS",
            "task_unit_count": len(items),
            "completed_item_count": len(results),
            "complete": False,
        }
    final = output.resolve() / "final"
    if final.exists():
        verify_bundle(final)
        return read_json(final / "report.json")
    result_by_task = _unique_results(results, "contract content reviews")
    frozen = []
    for task_id in sorted(tasks):
        row = result_by_task[task_id]
        contract = rows[task_id]
        review_core = {
            "schema_version": "contract-content-review-1.0",
            "task_unit_id": task_id,
            "contract_id": contract["contract_id"],
            **{key: value for key, value in row.items() if key != "task_unit_id"},
            "terminal_quality_decision": _terminal_quality(row),
            "arms_or_outcomes_used": False,
        }
        frozen.append(
            {**review_core, "contract_content_review_record_sha256": content_hash(review_core)}
        )
    terminal = sum(row["terminal_quality_decision"] is not None for row in frozen)
    report = {
        "schema_version": "1.0",
        "status": "CONTRACT_CONTENT_REVIEW_FROZEN",
        "base_bundle_sha256": _manifest_digest(base),
        "proposals_bundle_sha256": bundle_digest(proposals),
        "task_unit_count": len(items),
        "terminal_quality_decision_count": terminal,
        "nonterminal_count": len(items) - terminal,
        "contract_status_counts": dict(sorted(Counter(row["contract_status"] for row in frozen).items())),
        "evidence_status_counts": dict(sorted(Counter(row["evidence_status"] for row in frozen).items())),
        "source_specification_disposition_counts": dict(
            sorted(Counter(row["source_specification_disposition"] for row in frozen).items())
        ),
        "quality_disposition_counts": dict(
            sorted(
                Counter(
                    row["terminal_quality_decision"]
                    for row in frozen
                    if row["terminal_quality_decision"] is not None
                ).items()
            )
        ),
        "review_plan_sha256": content_hash(plan),
        "arms_or_outcomes_used": False,
        "formal_roles_used": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(final, {"contract-content-reviews.json": frozen, "report.json": report})
    return report


def run_single_task_semantic_repairs(
    repository_root: Path,
    base_bundle: Path,
    evidence_root: Path,
    output: Path,
    *,
    producer_commit: str,
    max_new_batches: int | None = None,
    workers: int = 1,
    provider: Provider = bailian_complete,
) -> dict[str, Any]:
    """Repair only faulty or evidence-escalated contracts, one task per request."""

    if not producer_commit or any(character.isspace() for character in producer_commit):
        raise ValueError("producer_commit must be one non-empty token")
    base = base_bundle.resolve()
    verify_task_unit_data(base)
    tasks, contracts, quality = _base_population(base)
    items = _cleaning_items(tasks, contracts, quality)
    evidence_items = [item for item in items if item["mode"] == "EVIDENCE_BACKFILL_ONLY"]
    evidence_results, evidence_plan = _load_closed_stage(
        evidence_root.resolve(),
        expected_stage="contract_evidence_backfill",
        expected_task_ids={item["task_unit_id"] for item in evidence_items},
    )
    if evidence_plan.get("base_bundle_sha256") != _manifest_digest(base):
        raise ContractCleaningError("evidence stage does not bind the base data bundle")
    evidence_by_task = _unique_results(evidence_results, "evidence backfill")
    escalated = {
        task_id
        for task_id, row in evidence_by_task.items()
        if row["binding_status"] == "needs_repair"
    }
    repair_items = sorted(
        [item for item in items if item["mode"] == "SEMANTIC_REPAIR"]
        + [item for item in evidence_items if item["task_unit_id"] in escalated],
        key=lambda item: item["task_unit_id"],
    )
    results, complete, plan = _run_stage(
        repository_root,
        output.resolve(),
        repair_items,
        prompt_name="contract-semantic-repair-v1.txt",
        config_name="contract-cleaning-producer-qwen35flash.json",
        stage="single_task_contract_semantic_repair_without_evidence",
        base_identity={
            "schema_version": "1.0",
            "base_bundle_sha256": _manifest_digest(base),
            "evidence_plan_bundle_sha256": bundle_digest(evidence_root.resolve() / "plan"),
            "evidence_result_count": len(evidence_results),
            "repair_item_count": len(repair_items),
            "producer_commit": producer_commit,
            "arms_or_outcomes_used": False,
            "formal_roles_used": False,
        },
        request_builder=_repair_request,
        parser=_parse_contract_repairs,
        max_new_batches=max_new_batches,
        workers=workers,
        provider=provider,
        batch_items=1,
    )
    if not complete:
        return {
            "schema_version": "1.0",
            "status": "SINGLE_TASK_SEMANTIC_REPAIR_IN_PROGRESS",
            "repair_item_count": len(repair_items),
            "completed_repair_item_count": len(results),
            "complete": False,
        }
    final = output.resolve() / "final"
    if final.exists():
        verify_bundle(final)
        return read_json(final / "report.json")
    repairs = [row for _, row in sorted(_unique_results(results, "semantic repairs").items())]
    report = {
        "schema_version": "1.0",
        "status": "SINGLE_TASK_SEMANTIC_REPAIRS_FROZEN",
        "base_bundle_sha256": _manifest_digest(base),
        "evidence_plan_bundle_sha256": bundle_digest(evidence_root.resolve() / "plan"),
        "repair_item_count": len(repairs),
        "source_specification_assessment_counts": dict(
            sorted(Counter(row["source_specification_assessment"] for row in repairs).items())
        ),
        "discarded_out_of_scope_evidence_count": sum(
            row["discarded_out_of_scope_evidence"] for row in repairs
        ),
        "repair_plan_sha256": content_hash(plan),
        "producer_commit": producer_commit,
        "arms_or_outcomes_used": False,
        "formal_roles_used": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(final, {"semantic-contract-repairs.json": repairs, "report.json": report})
    return report


def run_repaired_contract_evidence(
    repository_root: Path,
    base_bundle: Path,
    repairs_root: Path,
    output: Path,
    *,
    producer_commit: str,
    max_new_batches: int | None = None,
    workers: int = 1,
    provider: Provider = bailian_complete,
) -> dict[str, Any]:
    """Bind exact source spans to immutable repaired contracts, one task per request."""

    base = base_bundle.resolve()
    repairs_bundle = repairs_root.resolve()
    verify_task_unit_data(base)
    verify_bundle(repairs_bundle)
    tasks, _, _ = _base_population(base)
    repairs = _unique_by(
        read_json(repairs_bundle / "semantic-contract-repairs.json"),
        "task_unit_id",
        "semantic contract repairs",
    )
    if not set(repairs) <= set(tasks):
        raise ContractCleaningError("semantic repairs leave the base task population")
    items = []
    for task_id, repair in sorted(repairs.items()):
        task = tasks[task_id]
        items.append(
            {
                "task_unit_id": task_id,
                "language": task["declared_execution_context"]["language"],
                "source_prompt": task["model_visible_input"]["natural_prompt"],
                "source_prompt_sha256": task["model_visible_input"][
                    "natural_prompt_content_sha256"
                ],
                "old_contract": {
                    key: repair[key]
                    for key in ("resolution_status", "entrypoint", *_CONTENT_FIELDS)
                },
            }
        )
    results, complete, plan = _run_stage(
        repository_root,
        output.resolve(),
        items,
        prompt_name="contract-evidence-backfill-v1.txt",
        config_name="contract-cleaning-producer-qwen35flash.json",
        stage="single_task_repaired_contract_evidence",
        base_identity={
            "schema_version": "1.0",
            "base_bundle_sha256": _manifest_digest(base),
            "repairs_bundle_sha256": bundle_digest(repairs_bundle),
            "repair_item_count": len(items),
            "producer_commit": producer_commit,
            "arms_or_outcomes_used": False,
            "formal_roles_used": False,
        },
        request_builder=_evidence_request,
        parser=_parse_evidence_backfill,
        max_new_batches=max_new_batches,
        workers=workers,
        provider=provider,
        batch_items=1,
    )
    if not complete:
        return {
            "schema_version": "1.0",
            "status": "REPAIRED_CONTRACT_EVIDENCE_IN_PROGRESS",
            "repair_item_count": len(items),
            "completed_item_count": len(results),
            "complete": False,
        }
    final = output.resolve() / "final"
    if final.exists():
        verify_bundle(final)
        return read_json(final / "report.json")
    evidence = [row for _, row in sorted(_unique_results(results, "repair evidence").items())]
    bound = sum(row["binding_status"] == "bound" for row in evidence)
    report = {
        "schema_version": "1.0",
        "status": "REPAIRED_CONTRACT_EVIDENCE_FROZEN",
        "repair_item_count": len(evidence),
        "evidence_bound_count": bound,
        "evidence_unbound_count": len(evidence) - bound,
        "evidence_plan_sha256": content_hash(plan),
        "producer_commit": producer_commit,
        "arms_or_outcomes_used": False,
        "formal_roles_used": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(
        final,
        {"repaired-contract-evidence.json": evidence, "report.json": report},
    )
    return report


def adjudicate_unbound_repaired_contract_evidence(
    repository_root: Path,
    base_bundle: Path,
    repairs_root: Path,
    prior_evidence_root: Path,
    output: Path,
    *,
    producer_commit: str,
    max_new_batches: int | None = None,
    workers: int = 1,
    provider: Provider = bailian_complete,
) -> dict[str, Any]:
    """Close vacuous evidence and independently recheck only non-empty disputes."""

    if not producer_commit or any(character.isspace() for character in producer_commit):
        raise ValueError("producer_commit must be one non-empty token")
    base = base_bundle.resolve()
    repairs_bundle = repairs_root.resolve()
    prior_bundle = prior_evidence_root.resolve()
    verify_task_unit_data(base)
    verify_bundle(repairs_bundle)
    verify_bundle(prior_bundle)
    tasks, _, _ = _base_population(base)
    repairs = _unique_by(
        read_json(repairs_bundle / "semantic-contract-repairs.json"),
        "task_unit_id",
        "semantic contract repairs",
    )
    prior = _unique_by(
        read_json(prior_bundle / "repaired-contract-evidence.json"),
        "task_unit_id",
        "prior repaired contract evidence",
    )
    if set(repairs) != set(prior) or not set(repairs) <= set(tasks):
        raise ContractCleaningError("evidence adjudication populations differ")

    carried: dict[str, dict[str, Any]] = {}
    items = []
    vacuous = 0
    for task_id, repair in sorted(repairs.items()):
        task = tasks[task_id]
        contract = {
            key: repair[key]
            for key in ("resolution_status", "entrypoint", *_CONTENT_FIELDS)
        }
        prior_row = prior[task_id]
        if prior_row.get("binding_status") == "bound":
            carried[task_id] = {**prior_row, "evidence_adjudication": "PRIOR_BOUND"}
            continue
        if prior_row.get("binding_status") != "needs_repair":
            raise ContractCleaningError("prior evidence status is invalid")
        if not _evidence_targets(contract):
            empty = _normalize_evidence_bindings(
                [],
                contract,
                task["model_visible_input"]["natural_prompt"],
                task["model_visible_input"]["natural_prompt_content_sha256"],
            )
            carried[task_id] = {
                "task_unit_id": task_id,
                "binding_status": "bound",
                "model_binding_status": prior_row.get("model_binding_status"),
                "content_evidence": empty,
                "reason": "No non-empty contract value requires a source span.",
                "evidence_adjudication": "VACUOUS_NO_TARGETS",
            }
            vacuous += 1
            continue
        items.append(
            {
                "task_unit_id": task_id,
                "language": task["declared_execution_context"]["language"],
                "source_prompt": task["model_visible_input"]["natural_prompt"],
                "source_prompt_sha256": task["model_visible_input"][
                    "natural_prompt_content_sha256"
                ],
                "old_contract": contract,
            }
        )

    results, complete, plan = _run_stage(
        repository_root,
        output.resolve(),
        items,
        prompt_name="contract-evidence-backfill-v1.txt",
        config_name="contract-cleaning-reviewer-qwen37max.json",
        stage="unbound_repaired_contract_evidence_adjudication",
        base_identity={
            "schema_version": "1.0",
            "base_bundle_sha256": _manifest_digest(base),
            "repairs_bundle_sha256": bundle_digest(repairs_bundle),
            "prior_evidence_bundle_sha256": bundle_digest(prior_bundle),
            "prior_bound_count": len(carried) - vacuous,
            "vacuous_no_target_count": vacuous,
            "adjudication_item_count": len(items),
            "producer_commit": producer_commit,
            "arms_or_outcomes_used": False,
            "formal_roles_used": False,
        },
        request_builder=_evidence_request,
        parser=_parse_evidence_backfill,
        max_new_batches=max_new_batches,
        workers=workers,
        provider=provider,
        batch_items=1,
    )
    if not complete:
        return {
            "schema_version": "1.0",
            "status": "REPAIRED_CONTRACT_EVIDENCE_ADJUDICATION_IN_PROGRESS",
            "repair_item_count": len(repairs),
            "prior_bound_count": len(carried) - vacuous,
            "vacuous_no_target_count": vacuous,
            "adjudication_item_count": len(items),
            "completed_adjudication_item_count": len(results),
            "complete": False,
        }
    final = output.resolve() / "final"
    if final.exists():
        verify_bundle(final)
        return read_json(final / "report.json")
    adjudicated = {
        task_id: {**row, "evidence_adjudication": "QWEN37MAX_ADJUDICATION"}
        for task_id, row in _unique_results(results, "evidence adjudication").items()
    }
    merged = {**carried, **adjudicated}
    if set(merged) != set(repairs):
        raise ContractCleaningError("evidence adjudication does not cover every repair")
    evidence = [row for _, row in sorted(merged.items())]
    bound = sum(row["binding_status"] == "bound" for row in evidence)
    report = {
        "schema_version": "1.0",
        "status": "REPAIRED_CONTRACT_EVIDENCE_ADJUDICATION_FROZEN",
        "repair_item_count": len(evidence),
        "prior_bound_count": len(carried) - vacuous,
        "vacuous_no_target_count": vacuous,
        "adjudication_item_count": len(items),
        "adjudication_bound_count": sum(
            row["binding_status"] == "bound" for row in adjudicated.values()
        ),
        "evidence_bound_count": bound,
        "evidence_unbound_count": len(evidence) - bound,
        "adjudication_plan_sha256": content_hash(plan),
        "producer_commit": producer_commit,
        "arms_or_outcomes_used": False,
        "formal_roles_used": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(
        final,
        {"repaired-contract-evidence.json": evidence, "report.json": report},
    )
    return report


def assemble_contract_content_proposals(
    base_bundle: Path,
    evidence_root: Path,
    repairs_root: Path,
    repair_evidence_root: Path,
    output: Path,
    *,
    producer_commit: str,
) -> dict[str, Any]:
    """Combine the closed evidence and one-task repair stages into one proposal bundle."""

    base = base_bundle.resolve()
    repairs_bundle = repairs_root.resolve()
    repair_evidence_bundle = repair_evidence_root.resolve()
    verify_task_unit_data(base)
    verify_bundle(repairs_bundle)
    verify_bundle(repair_evidence_bundle)
    tasks, contracts, quality = _base_population(base)
    items = _cleaning_items(tasks, contracts, quality)
    evidence_items = [item for item in items if item["mode"] == "EVIDENCE_BACKFILL_ONLY"]
    evidence_results, _ = _load_closed_stage(
        evidence_root.resolve(),
        expected_stage="contract_evidence_backfill",
        expected_task_ids={item["task_unit_id"] for item in evidence_items},
    )
    evidence_by_task = _unique_results(evidence_results, "evidence backfill")
    repair_by_task = _unique_by(
        read_json(repairs_bundle / "semantic-contract-repairs.json"),
        "task_unit_id",
        "semantic repairs",
    )
    escalated = {
        task_id
        for task_id, row in evidence_by_task.items()
        if row["binding_status"] == "needs_repair"
    }
    expected_repairs = {
        item["task_unit_id"]
        for item in items
        if item["mode"] == "SEMANTIC_REPAIR" or item["task_unit_id"] in escalated
    }
    if set(repair_by_task) != expected_repairs:
        raise ContractCleaningError("semantic repair population is incomplete")
    repair_evidence_by_task = _unique_by(
        read_json(repair_evidence_bundle / "repaired-contract-evidence.json"),
        "task_unit_id",
        "repaired contract evidence",
    )
    if set(repair_evidence_by_task) != expected_repairs or any(
        row.get("binding_status") != "bound" for row in repair_evidence_by_task.values()
    ):
        raise ContractCleaningError("repaired contract evidence is incomplete")
    proposed = []
    ledger = []
    for item in items:
        task_id = item["task_unit_id"]
        evidence_row = evidence_by_task.get(task_id)
        if evidence_row is not None and evidence_row["binding_status"] == "bound":
            mode = "EVIDENCE_BACKFILL_ONLY"
            values = item["old_contract"]
            evidence = evidence_row["content_evidence"]
            assessment = "sufficient"
            category = "EVIDENCE_BACKFILL_ONLY"
            reason = evidence_row["reason"]
        else:
            repair = repair_by_task[task_id]
            mode = "SEMANTIC_REPAIR"
            values = {
                key: repair[key]
                for key in ("resolution_status", "entrypoint", *_CONTENT_FIELDS)
            }
            evidence = repair_evidence_by_task[task_id]["content_evidence"]
            assessment = repair["source_specification_assessment"]
            category = repair["repair_category"]
            reason = repair["reason"]
        core = {
            "schema_version": "functional-contract-cleaning-proposal-1.0",
            "task_unit_id": task_id,
            "record_id": tasks[task_id]["representative_record_id"],
            "source_prompt_sha256": item["source_prompt_sha256"],
            **values,
            "content_evidence": evidence,
            "proposal_mode": mode,
            "producer_source_assessment": assessment,
            "producer_reason": reason,
            "arms_or_outcomes_used": False,
        }
        contract_id = content_id("functional_contract_", core)
        proposal = {**core, "contract_id": contract_id}
        proposed.append(proposal)
        ledger_core = {
            "schema_version": "contract-repair-ledger-1.0",
            "task_unit_id": task_id,
            "old_contract_id": item["old_contract_id"],
            "repair_category": category,
            "repair_status": "PROPOSED_PENDING_INDEPENDENT_REVIEW",
            "new_contract_id": contract_id,
            "source_specification_disposition": assessment,
            "evidence_span_count": _evidence_span_count(evidence),
            "review_status": "PENDING",
            "review_issue_codes": [],
            "input_sha256": content_hash(
                {
                    "task_unit_id": task_id,
                    "source_prompt_sha256": item["source_prompt_sha256"],
                    "old_contract_id": item["old_contract_id"],
                }
            ),
            "output_sha256": content_hash(proposal),
            "producer_commit": producer_commit,
        }
        ledger.append(
            {**ledger_core, "repair_ledger_record_sha256": content_hash(ledger_core)}
        )
    report = {
        "schema_version": "1.0",
        "status": "CONTRACT_CONTENT_PROPOSALS_FROZEN",
        "base_bundle_sha256": _manifest_digest(base),
        "task_unit_count": len(items),
        "evidence_only_count": len(items) - len(expected_repairs),
        "semantic_repair_count": len(expected_repairs),
        "evidence_escalation_count": len(escalated),
        "producer_source_assessment_counts": dict(
            sorted(Counter(row["producer_source_assessment"] for row in proposed).items())
        ),
        "producer_commit": producer_commit,
        "evidence_plan_bundle_sha256": bundle_digest(evidence_root.resolve() / "plan"),
        "repairs_bundle_sha256": bundle_digest(repairs_bundle),
        "repair_evidence_bundle_sha256": bundle_digest(repair_evidence_bundle),
        "all_task_units_accounted_for": len(proposed) == len(items),
        "arms_or_outcomes_used": False,
        "formal_roles_used": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(
        output.resolve(),
        {
            "proposed-contracts.json": proposed,
            "contract-repair-ledger.json": ledger,
            "report.json": report,
        },
    )
    return report


def finalize_contract_content_data(
    base_bundle: Path,
    proposals_root: Path,
    reviews_root: Path,
    reservation_root: Path,
    output: Path,
    *,
    producer_commit: str,
) -> dict[str, Any]:
    """Build the single terminal reviewer data set after outcome-blind contract review."""

    if not producer_commit or any(character.isspace() for character in producer_commit):
        raise ValueError("producer_commit must be one non-empty token")
    base = base_bundle.resolve()
    proposals = proposals_root.resolve()
    reviews = reviews_root.resolve()
    reservation = reservation_root.resolve()
    verify_task_unit_data(base)
    for root in (proposals, reviews, reservation):
        verify_bundle(root)
    tasks = _unique_by(
        _canonical_jsonl(base / "task-units.jsonl", "tasks"), "task_unit_id", "tasks"
    )
    old_roles = _unique_by(
        _canonical_jsonl(base / "task-roles.jsonl", "roles"), "task_unit_id", "roles"
    )
    old_readiness = _unique_by(
        _canonical_jsonl(base / "readiness-worklist.jsonl", "readiness"),
        "task_unit_id",
        "readiness",
    )
    proposals_by_task = _unique_by(
        read_json(proposals / "proposed-contracts.json"),
        "task_unit_id",
        "proposed contracts",
    )
    proposal_ledger = _unique_by(
        read_json(proposals / "contract-repair-ledger.json"),
        "task_unit_id",
        "proposal ledger",
    )
    reviews_by_task = _unique_by(
        read_json(reviews / "contract-content-reviews.json"),
        "task_unit_id",
        "content reviews",
    )
    reservations = _unique_by(
        read_json(reservation / "reservations.json"),
        "task_unit_id",
        "future-evaluation reservations",
    )
    population = set(tasks)
    if (
        set(old_roles) != population
        or set(old_readiness) != population
        or set(proposals_by_task) != population
        or set(proposal_ledger) != population
        or set(reviews_by_task) != population
        or not set(reservations) <= population
    ):
        raise ContractCleaningError("final contract-cleaning populations differ")
    group_rows = _canonical_jsonl(
        base / "near-duplicate-groups.jsonl", "near-duplicate groups"
    )
    reserved_groups = {row["near_duplicate_group_id"] for row in reservations.values()}
    if len(reserved_groups) != len(reservations):
        raise ContractCleaningError("future-evaluation reservation groups are duplicated")

    final_tasks = []
    contracts = []
    quality = []
    roles = []
    readiness = []
    ledger = []
    for task_id in sorted(population):
        task = tasks[task_id]
        proposal = proposals_by_task[task_id]
        review = reviews_by_task[task_id]
        disposition = review.get("terminal_quality_decision")
        if disposition not in _TERMINAL_QUALITY:
            raise ContractCleaningError(
                "nonterminal contract review cannot enter the final data foundation"
            )
        if (
            proposal.get("contract_id") != review.get("contract_id")
            or proposal.get("record_id") != task.get("representative_record_id")
            or proposal.get("source_prompt_sha256")
            != task["model_visible_input"]["natural_prompt_content_sha256"]
        ):
            raise ContractCleaningError("final contract source or review binding is stale")
        _validate_proposal_identity(proposal)
        _validate_terminal_review(review)
        if proposal_ledger[task_id].get("new_contract_id") != proposal["contract_id"]:
            raise ContractCleaningError("proposal ledger does not bind the cleaned contract")
        _validate_frozen_evidence(task, proposal)
        task_core = {
            **{
                key: value
                for key, value in task.items()
                if key
                not in {
                    "schema_version",
                    "task_unit_record_sha256",
                    "evaluation_asset_refs",
                }
            },
            "schema_version": "task-unit-5.0",
            "evaluation_asset_refs": {
                **task["evaluation_asset_refs"],
                "functional_contract_id": proposal["contract_id"],
            },
        }
        final_tasks.append(
            {**task_core, "task_unit_record_sha256": content_hash(task_core)}
        )
        review_payload = {
            key: review[key]
            for key in (
                "contract_status",
                "evidence_status",
                "source_specification_disposition",
                "issue_codes",
                "repair_category",
                "reason",
                "terminal_quality_decision",
            )
        }
        contract_core = {
            "schema_version": "functional-contract-reviewer-5.0",
            "task_unit_id": task_id,
            "contract_id": proposal["contract_id"],
            "record_id": proposal["record_id"],
            "source_prompt_sha256": proposal["source_prompt_sha256"],
            **_proposal_payload(proposal),
            "producer_reason": proposal["producer_reason"],
            "proposal_mode": proposal["proposal_mode"],
            "requirement_evidence_status": "SOURCE_SPANS_COMPLETE_UTF8_BYTES",
            "review": review_payload,
            "provenance": {
                "base_bundle_sha256": _manifest_digest(base),
                "proposals_bundle_sha256": bundle_digest(proposals),
                "reviews_bundle_sha256": bundle_digest(reviews),
            },
            "arms_or_outcomes_used": False,
        }
        contract_row = {
            **contract_core,
            "functional_contract_record_sha256": content_hash(contract_core),
        }
        contracts.append(contract_row)

        quality_core = {
            "schema_version": "task-quality-5.0",
            "task_unit_id": task_id,
            "quality_disposition": disposition,
            "contract_id": proposal["contract_id"],
            "contract_quality": "STRICT_SOURCE_BOUND",
            "review_contract_status": review["contract_status"],
            "functional_evaluability": (
                "sufficient" if disposition == "QUALITY_INCLUDED" else "insufficient"
            ),
            "reason_codes": {
                "QUALITY_INCLUDED": [],
                "QUALITY_EXCLUDED_SOURCE_DEFECT": ["source_defect"],
                "QUALITY_EXCLUDED_INSUFFICIENT_SPECIFICATION": [
                    "insufficient_specification"
                ],
            }[disposition],
            "authority_boundary": (
                "source_and_contract_quality_only_not_scope_measurement_exposure_or_role"
            ),
            "decision_provenance": {
                "contract_record_sha256": contract_row[
                    "functional_contract_record_sha256"
                ],
                "contract_content_review_record_sha256": review[
                    "contract_content_review_record_sha256"
                ],
            },
            "arms_or_outcomes_used": False,
        }
        quality.append(
            {**quality_core, "task_quality_record_sha256": content_hash(quality_core)}
        )

        old_role = old_roles[task_id]
        categories = sorted(
            set(old_role["exposure_categories"]) | {"CONTRACT_REPAIR_VIEWED"}
        )
        reserved = task_id in reservations
        role_core = {
            **{
                key: value
                for key, value in old_role.items()
                if key
                not in {
                    "schema_version",
                    "task_role_record_sha256",
                    "exposure_categories",
                    "prospective_confirmatory_reuse_status",
                }
            },
            "schema_version": "task-role-5.0",
            "exposure_categories": categories,
            "prospective_confirmatory_reuse_status": (
                "RESERVED_CURATION_ONLY_PENDING_FORMAL_ALLOCATION"
                if reserved
                else old_role["prospective_confirmatory_reuse_status"]
            ),
            "future_evaluation_reservation_id": (
                reservations[task_id]["future_evaluation_reservation_record_sha256"]
                if reserved
                else None
            ),
        }
        roles.append(
            {**role_core, "task_role_record_sha256": content_hash(role_core)}
        )

        readiness_row = _final_readiness_row(
            old_readiness[task_id], disposition, proposal["contract_id"]
        )
        readiness.append(readiness_row)

        old_ledger = proposal_ledger[task_id]
        ledger_core = {
            **{
                key: value
                for key, value in old_ledger.items()
                if key != "repair_ledger_record_sha256"
            },
            "schema_version": "contract-repair-ledger-1.1",
            "repair_status": "INDEPENDENTLY_REVIEWED_TERMINAL",
            "review_status": "TERMINAL",
            "review_issue_codes": review["issue_codes"],
            "final_quality_disposition": disposition,
            "independent_review_record_sha256": review[
                "contract_content_review_record_sha256"
            ],
        }
        ledger.append(
            {**ledger_core, "repair_ledger_record_sha256": content_hash(ledger_core)}
        )

    quality_counts = dict(
        sorted(Counter(row["quality_disposition"] for row in quality).items())
    )
    readiness_counts = dict(sorted(Counter(row["workstream"] for row in readiness).items()))
    report = {
        "schema_version": "5.0",
        "status": "DATA_FOUNDATION_COMPLETE_PROMPT_TSG_DEFERRED",
        "source_record_count": read_json(base / "report.json")["source_record_count"],
        "task_unit_count": len(tasks),
        "functional_contract_count": len(contracts),
        "content_evidence_complete_count": len(contracts),
        "contract_repair_ledger_count": len(ledger),
        "quality_disposition_counts": quality_counts,
        "pending_quality_count": 0,
        "future_evaluation_reserved_task_unit_count": len(reservations),
        "future_evaluation_reserved_group_count": len(reserved_groups),
        "readiness_workstream_counts": readiness_counts,
        "readiness_axis_counts": {
            field: dict(sorted(Counter(row[field] for row in readiness).items()))
            for field in (
                "quality_gate",
                "scope_status",
                "mechanism_registration_status",
                "binding_status",
                "oracle_status",
                "runtime_status",
                "functional_measurement_status",
                "independent_quality_review_status",
            )
        },
        "prompt_tsg": {
            "status": "NOT_GENERATED_PENDING_METHOD_FREEZE",
            "extractor_id": None,
            "catalog_sha256": None,
            "task_count": 0,
        },
        "input_bundles": {
            "base_bundle_sha256": _manifest_digest(base),
            "proposals_bundle_sha256": bundle_digest(proposals),
            "reviews_bundle_sha256": bundle_digest(reviews),
            "reservation_bundle_sha256": bundle_digest(reservation),
        },
        "producer_commit": producer_commit,
        "referential_integrity": {
            "core_task_unit_populations_equal": True,
            "contracts_prompt_hash_bound": True,
            "task_contract_reference_current": True,
            "quality_contract_version_bound": True,
            "repair_ledger_review_bound": True,
            "near_duplicate_groups_unchanged": True,
            "source_lineages_unchanged": True,
            "downstream_experimental_fields_absent": True,
        },
        "arms_or_outcomes_used": False,
        "formal_role_assignment_frozen": False,
        "formal_execution_authorized": False,
        "scientific_effect_claim_allowed": False,
    }
    artifacts = {
        "task-units.jsonl": final_tasks,
        "functional-contracts.jsonl": contracts,
        "task-quality.jsonl": quality,
        "task-roles.jsonl": roles,
        "source-lineages.jsonl": _canonical_jsonl(
            base / "source-lineages.jsonl", "source lineages"
        ),
        "near-duplicate-groups.jsonl": group_rows,
        "readiness-worklist.jsonl": readiness,
        "contract-repair-ledger.jsonl": ledger,
    }
    _write_final_data_bundle(output.resolve(), artifacts, report)
    return verify_contract_content_data(output.resolve())


def verify_contract_content_data(root: Path) -> dict[str, Any]:
    """Independently verify the terminal content-cleaned data foundation."""

    bundle = root.resolve()
    manifest = _canonical_json_object(bundle / "manifest.json", "manifest")
    if (
        manifest.get("schema_version") != "5.0"
        or manifest.get("artifact_kind") != "reviewer_task_unit_dataset"
        or set(manifest.get("files", {})) != _FINAL_FILES
    ):
        raise ContractCleaningError("final data manifest is invalid")
    actual = {
        path.name for path in bundle.iterdir() if path.is_file() and path.name != "manifest.json"
    }
    if actual != _FINAL_FILES:
        raise ContractCleaningError("final data file set is not exact")
    rows_by_file = {}
    for name in sorted(_FINAL_JSONL_FILES):
        rows = _canonical_jsonl(bundle / name, name)
        descriptor = manifest["files"][name]
        if (
            descriptor.get("format") != "canonical-jsonl"
            or descriptor.get("record_count") != len(rows)
            or descriptor.get("sha256")
            != hashlib.sha256((bundle / name).read_bytes()).hexdigest()
        ):
            raise ContractCleaningError(f"{name} manifest identity drift")
        rows_by_file[name] = rows
    report = _canonical_json_object(bundle / "report.json", "report")
    if (
        manifest["files"]["report.json"].get("format") != "canonical-json"
        or manifest["files"]["report.json"].get("sha256")
        != hashlib.sha256((bundle / "report.json").read_bytes()).hexdigest()
    ):
        raise ContractCleaningError("final report manifest identity drift")
    tasks = _unique_by(rows_by_file["task-units.jsonl"], "task_unit_id", "tasks")
    contracts = _unique_by(
        rows_by_file["functional-contracts.jsonl"], "task_unit_id", "contracts"
    )
    quality = _unique_by(rows_by_file["task-quality.jsonl"], "task_unit_id", "quality")
    roles = _unique_by(rows_by_file["task-roles.jsonl"], "task_unit_id", "roles")
    readiness = _unique_by(
        rows_by_file["readiness-worklist.jsonl"], "task_unit_id", "readiness"
    )
    ledger = _unique_by(
        rows_by_file["contract-repair-ledger.jsonl"], "task_unit_id", "repair ledger"
    )
    if any(set(rows) != set(tasks) for rows in (contracts, quality, roles, readiness, ledger)):
        raise ContractCleaningError("final data populations differ")
    forbidden_fields = {
        "task_id",
        "confirm_add_eligible",
        "confirm_remove_eligible",
        "eligible_arm_protocol_ids",
        "split",
        "prompt_tsg",
        "assignment",
        "generated_code",
        "outcome",
    }
    if any(
        forbidden_fields.intersection(row)
        for rows in (tasks, contracts, quality, roles)
        for row in rows.values()
    ):
        raise ContractCleaningError("downstream experimental field entered final data")
    group_rows = _unique_by(
        rows_by_file["near-duplicate-groups.jsonl"],
        "near_duplicate_group_id",
        "near-duplicate groups",
    )
    lineage_rows = _unique_by(
        rows_by_file["source-lineages.jsonl"], "source_lineage_id", "source lineages"
    )
    task_to_group = {}
    for group_id, group in group_rows.items():
        core = {
            key: value
            for key, value in group.items()
            if key != "near_duplicate_group_record_sha256"
        }
        if (
            group.get("schema_version") != "near-duplicate-group-4.0"
            or group.get("near_duplicate_group_record_sha256") != content_hash(core)
            or group.get("maximum_task_units_across_all_prospective_formal_roles") != 1
        ):
            raise ContractCleaningError("near-duplicate group is invalid")
        for task_id in group.get("task_unit_ids", []):
            if task_id in task_to_group:
                raise ContractCleaningError("near-duplicate groups overlap")
            task_to_group[task_id] = group_id
    task_to_lineage = {}
    for lineage_id, lineage in lineage_rows.items():
        core = {key: value for key, value in lineage.items() if key != "lineage_record_sha256"}
        if (
            lineage.get("schema_version") != "source-lineage-3.0"
            or lineage.get("lineage_record_sha256") != content_hash(core)
        ):
            raise ContractCleaningError("source lineage is invalid")
        for task_id in lineage.get("task_unit_ids", []):
            if task_id in task_to_lineage:
                raise ContractCleaningError("source lineages overlap")
            task_to_lineage[task_id] = lineage_id
    if set(task_to_group) != set(tasks) or set(task_to_lineage) != set(tasks):
        raise ContractCleaningError("groups or lineages do not partition final tasks")
    source_record_ids = []
    for task_id, task in tasks.items():
        contract = contracts[task_id]
        quality_row = quality[task_id]
        role = roles[task_id]
        readiness_row = readiness[task_id]
        ledger_row = ledger[task_id]
        _validate_frozen_evidence(task, contract)
        _validate_final_contract_identity(contract)
        review_identity = _review_identity_from_final_contract(contract)
        if (
            task.get("schema_version") != "task-unit-5.0"
            or task.get("task_unit_record_sha256")
            != content_hash(
                {
                    key: value
                    for key, value in task.items()
                    if key != "task_unit_record_sha256"
                }
            )
            or task.get("evaluation_asset_refs", {}).get("functional_contract_id")
            != contract.get("contract_id")
            or task.get("model_visible_input", {}).get("natural_prompt_content_sha256")
            != content_hash(task.get("model_visible_input", {}).get("natural_prompt"))
            or contract.get("record_id") != task.get("representative_record_id")
            or contract.get("schema_version") != "functional-contract-reviewer-5.0"
            or contract.get("functional_contract_record_sha256")
            != content_hash(
                {
                    key: value
                    for key, value in contract.items()
                    if key != "functional_contract_record_sha256"
                }
            )
            or quality_row.get("schema_version") != "task-quality-5.0"
            or quality_row.get("quality_disposition") not in _TERMINAL_QUALITY
            or quality_row.get("contract_id") != contract.get("contract_id")
            or quality_row.get("task_quality_record_sha256")
            != content_hash(
                {
                    key: value
                    for key, value in quality_row.items()
                    if key != "task_quality_record_sha256"
                }
            )
            or role.get("schema_version") != "task-role-5.0"
            or "CONTRACT_REPAIR_VIEWED" not in role.get("exposure_categories", [])
            or role.get("prospective_formal_role_assigned") is not False
            or role.get("near_duplicate_group_id") != task_to_group[task_id]
            or role.get("source_lineage_id") != task_to_lineage[task_id]
            or role.get("task_role_record_sha256")
            != content_hash(
                {
                    key: value
                    for key, value in role.items()
                    if key != "task_role_record_sha256"
                }
            )
            or readiness_row.get("schema_version") != "readiness-work-item-5.0"
            or readiness_row.get("contract_id") != contract.get("contract_id")
            or readiness_row.get("readiness_record_sha256")
            != content_hash(
                {
                    key: value
                    for key, value in readiness_row.items()
                    if key != "readiness_record_sha256"
                }
            )
            or ledger_row.get("repair_status") != "INDEPENDENTLY_REVIEWED_TERMINAL"
            or ledger_row.get("final_quality_disposition")
            != quality_row.get("quality_disposition")
            or ledger_row.get("independent_review_record_sha256")
            != content_hash(review_identity)
            or ledger_row.get("repair_ledger_record_sha256")
            != content_hash(
                {
                    key: value
                    for key, value in ledger_row.items()
                    if key != "repair_ledger_record_sha256"
                }
            )
        ):
            raise ContractCleaningError("final data record binding is invalid")
        source_record_ids.extend(task.get("legacy_identity", {}).get("source_record_ids", []))
    if len(source_record_ids) != len(set(source_record_ids)):
        raise ContractCleaningError("source records are duplicated across final task units")
    for group in group_rows.values():
        if (
            sum(
                bool(roles[task_id].get("prospective_formal_role_assigned"))
                for task_id in group["task_unit_ids"]
            )
            > 1
        ):
            raise ContractCleaningError("near-duplicate formal-role firewall is violated")
    if (
        report.get("status") != "DATA_FOUNDATION_COMPLETE_PROMPT_TSG_DEFERRED"
        or report.get("task_unit_count") != len(tasks)
        or report.get("functional_contract_count") != len(contracts)
        or report.get("content_evidence_complete_count") != len(contracts)
        or report.get("contract_repair_ledger_count") != len(ledger)
        or report.get("pending_quality_count") != 0
        or report.get("quality_disposition_counts")
        != dict(sorted(Counter(row["quality_disposition"] for row in quality.values()).items()))
        or report.get("arms_or_outcomes_used") is not False
        or report.get("formal_execution_authorized") is not False
        or report.get("referential_integrity")
        != {
            "core_task_unit_populations_equal": True,
            "contracts_prompt_hash_bound": True,
            "task_contract_reference_current": True,
            "quality_contract_version_bound": True,
            "repair_ledger_review_bound": True,
            "near_duplicate_groups_unchanged": True,
            "source_lineages_unchanged": True,
            "downstream_experimental_fields_absent": True,
        }
        or report.get("prompt_tsg", {}).get("status")
        != "NOT_GENERATED_PENDING_METHOD_FREEZE"
    ):
        raise ContractCleaningError("final data report is invalid")
    return {
        "status": "VERIFIED_DATA_FOUNDATION_COMPLETE_PROMPT_TSG_DEFERRED",
        "bundle_sha256": hashlib.sha256((bundle / "manifest.json").read_bytes()).hexdigest(),
        "task_units": len(tasks),
        "functional_contracts": len(contracts),
        "quality_disposition_counts": report["quality_disposition_counts"],
        "future_evaluation_reserved_task_unit_count": report[
            "future_evaluation_reserved_task_unit_count"
        ],
        "prompt_tsg_status": report["prompt_tsg"]["status"],
        "arms_or_outcomes_used": False,
        "formal_execution_authorized": False,
    }


def _run_stage(
    repository_root: Path,
    output: Path,
    items: Sequence[dict[str, Any]],
    *,
    prompt_name: str,
    config_name: str,
    stage: str,
    base_identity: dict[str, Any],
    request_builder: Callable[[Sequence[dict[str, Any]]], dict[str, Any]],
    parser: Callable[[bytes, Sequence[dict[str, Any]]], list[dict[str, Any]]],
    max_new_batches: int | None,
    workers: int,
    provider: Provider,
    batch_items: int = _BATCH_ITEMS,
) -> tuple[list[dict[str, Any]], bool, dict[str, Any]]:
    evaluator, prompt, policy = _policy(repository_root, prompt_name, config_name)
    batches = _batches(items, "task_unit_id", batch_items, _item_chars)
    plan = {
        **base_identity,
        "stage": stage,
        "batch_item_limit": batch_items,
        "batch_ids": [[item["task_unit_id"] for item in batch] for batch in batches],
        "policy": policy,
    }
    run_root = _initialize(output, plan)
    results, complete = _execute(
        run_root,
        batches,
        evaluator,
        prompt,
        request_builder,
        parser,
        max_new_batches,
        workers,
        _transport_retry(provider),
    )
    return results, complete, plan


def _policy(root: Path, prompt_name: str, config_name: str) -> tuple[dict[str, Any], str, dict[str, Any]]:
    repository = root.resolve()
    prompt_path = repository / "data/dataset-curation" / prompt_name
    config_path = repository / "data/dataset-curation" / config_name
    evaluator = read_json(config_path)
    prompt = prompt_path.read_text(encoding="utf-8").strip()
    if not isinstance(evaluator, dict) or not prompt:
        raise ContractCleaningError("contract cleaning policy is invalid")
    identity = {
        "model_id": evaluator["model_id"],
        "config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
        "prompt_sha256": hashlib.sha256(prompt_path.read_bytes()).hexdigest(),
        "implementation_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "temperature": evaluator["temperature"],
        "top_p": evaluator["top_p"],
        "seed": evaluator["seed"],
        "transport_max_attempts": 3,
        "duplicate_index_policy": "last_occurrence_wins_if_all_indices_covered_v1",
    }
    return evaluator, prompt, identity


def _transport_retry(provider: Provider) -> Provider:
    """Retry only empty/invalid provider envelopes; semantic parsing remains single-pass."""

    def wrapped(
        request: dict[str, Any], evaluator: Mapping[str, Any], prompt: str
    ) -> bytes:
        last_failure: JudgeGateError | None = None
        for attempt in range(1, 4):
            try:
                return provider(request, evaluator, prompt)
            except JudgeGateError as failure:
                if str(failure) not in {
                    "provider request failed",
                    "provider response format is invalid",
                }:
                    raise
                last_failure = failure
                if attempt < 3:
                    time.sleep(float(attempt))
        assert last_failure is not None
        raise last_failure

    return wrapped


def _base_population(
    root: Path,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    tasks = _unique_by(_canonical_jsonl(root / "task-units.jsonl", "tasks"), "task_unit_id", "tasks")
    contracts = _unique_by(
        _canonical_jsonl(root / "functional-contracts.jsonl", "contracts"),
        "task_unit_id",
        "contracts",
    )
    quality = _unique_by(
        _canonical_jsonl(root / "task-quality.jsonl", "quality"), "task_unit_id", "quality"
    )
    if set(tasks) != set(contracts) or set(tasks) != set(quality):
        raise ContractCleaningError("base data populations differ")
    return tasks, contracts, quality


def _cleaning_items(
    tasks: Mapping[str, dict[str, Any]],
    contracts: Mapping[str, dict[str, Any]],
    quality: Mapping[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    items = []
    for task_id in sorted(tasks):
        task = tasks[task_id]
        contract = contracts[task_id]
        item = {
            "task_unit_id": task_id,
            "language": task["declared_execution_context"]["language"],
            "source_prompt": task["model_visible_input"]["natural_prompt"],
            "source_prompt_sha256": task["model_visible_input"][
                "natural_prompt_content_sha256"
            ],
            "old_contract": _contract_payload(contract),
            "old_contract_id": contract["contract_id"],
            "old_review": contract["review"],
            "old_quality_disposition": quality[task_id]["quality_disposition"],
            "mode": (
                "EVIDENCE_BACKFILL_ONLY"
                if contract["review"]["contract_status"] == "faithful"
                else "SEMANTIC_REPAIR"
            ),
        }
        items.append(item)
    return items


def _load_closed_stage(
    root: Path, *, expected_stage: str, expected_task_ids: set[str]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    verify_bundle(root / "plan")
    plan = read_json(root / "plan/plan.json")
    if plan.get("stage") != expected_stage:
        raise ContractCleaningError("closed curation stage identity is invalid")
    expected_batches = {
        f"batch-{index:04d}" for index in range(1, len(plan.get("batch_ids", [])) + 1)
    }
    batch_root = root / "batches"
    if not batch_root.is_dir() or {path.name for path in batch_root.iterdir()} != expected_batches:
        raise ContractCleaningError("closed curation stage batch set is incomplete")
    results = []
    for name in sorted(expected_batches):
        current = batch_root / name
        verify_bundle(current)
        result = read_json(current / "result.json")
        if result.get("status") != "COMPLETE":
            raise ContractCleaningError("closed curation stage contains an error")
        values = result.get("items")
        if not isinstance(values, list) or any(not isinstance(row, dict) for row in values):
            raise ContractCleaningError("closed curation stage result is invalid")
        results.extend(values)
    if set(_unique_results(results, "closed curation stage")) != expected_task_ids:
        raise ContractCleaningError("closed curation stage population is invalid")
    return results, plan


def _manifest_digest(root: Path) -> str:
    return hashlib.sha256((root / "manifest.json").read_bytes()).hexdigest()


def _validate_proposal_identity(proposal: Mapping[str, Any]) -> None:
    core = {key: value for key, value in proposal.items() if key != "contract_id"}
    if (
        proposal.get("schema_version")
        != "functional-contract-cleaning-proposal-1.0"
        or proposal.get("contract_id") != content_id("functional_contract_", core)
        or proposal.get("arms_or_outcomes_used") is not False
    ):
        raise ContractCleaningError("cleaned contract proposal identity is invalid")


def _validate_terminal_review(review: Mapping[str, Any]) -> None:
    core = {
        key: value
        for key, value in review.items()
        if key != "contract_content_review_record_sha256"
    }
    if (
        review.get("schema_version") != "contract-content-review-1.0"
        or review.get("contract_content_review_record_sha256") != content_hash(core)
        or review.get("arms_or_outcomes_used") is not False
        or review.get("terminal_quality_decision") != _terminal_quality(review)
        or review.get("terminal_quality_decision") not in _TERMINAL_QUALITY
        or review.get("issue_codes") != ["none"]
    ):
        raise ContractCleaningError("independent contract review is not terminal or valid")


def _proposal_identity_from_final_contract(contract: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "functional-contract-cleaning-proposal-1.0",
        "task_unit_id": contract["task_unit_id"],
        "record_id": contract["record_id"],
        "source_prompt_sha256": contract["source_prompt_sha256"],
        "resolution_status": contract["resolution_status"],
        "entrypoint": contract["entrypoint"],
        **{field: contract[field] for field in _CONTENT_FIELDS},
        "content_evidence": contract["content_evidence"],
        "proposal_mode": contract["proposal_mode"],
        "producer_source_assessment": contract["producer_source_assessment"],
        "producer_reason": contract["producer_reason"],
        "arms_or_outcomes_used": False,
    }


def _validate_final_contract_identity(contract: Mapping[str, Any]) -> None:
    if contract.get("contract_id") != content_id(
        "functional_contract_", _proposal_identity_from_final_contract(contract)
    ):
        raise ContractCleaningError("final cleaned contract identity is invalid")


def _review_identity_from_final_contract(contract: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "contract-content-review-1.0",
        "task_unit_id": contract["task_unit_id"],
        "contract_id": contract["contract_id"],
        **contract["review"],
        "arms_or_outcomes_used": False,
    }


def _validate_frozen_evidence(
    task: Mapping[str, Any], contract: Mapping[str, Any]
) -> None:
    prompt = task["model_visible_input"]["natural_prompt"]
    prompt_bytes = prompt.encode("utf-8")
    prompt_sha256 = task["model_visible_input"]["natural_prompt_content_sha256"]
    if contract.get("source_prompt_sha256") != prompt_sha256:
        raise ContractCleaningError("contract evidence prompt identity is stale")
    evidence = contract.get("content_evidence")
    if (
        not isinstance(evidence, dict)
        or evidence.get("offset_basis") != "utf8_bytes_of_exact_natural_prompt_v1"
        or set(evidence) != {"offset_basis", "entrypoint", *_CONTENT_FIELDS}
    ):
        raise ContractCleaningError("contract content evidence envelope is invalid")
    expected_groups: list[tuple[Any, Any]] = []
    expected_groups.append((contract.get("entrypoint"), evidence["entrypoint"]))
    for field in _CONTENT_FIELDS:
        values = contract.get(field)
        groups = evidence[field]
        if not isinstance(values, list) or not isinstance(groups, list) or len(values) != len(groups):
            raise ContractCleaningError("contract content evidence target count is invalid")
        expected_groups.extend(zip(values, groups, strict=True))
    for value, group in expected_groups:
        if value is None:
            if group != []:
                raise ContractCleaningError("absent contract value carries source evidence")
            continue
        if not isinstance(value, str) or not value.strip() or not isinstance(group, list) or not group:
            raise ContractCleaningError("contract value lacks source evidence")
        for span in group:
            if not isinstance(span, dict) or set(span) != {
                "source_prompt_sha256",
                "start_byte",
                "end_byte",
                "quoted_text",
                "span_sha256",
            }:
                raise ContractCleaningError("contract evidence span is malformed")
            start, end, quoted = span["start_byte"], span["end_byte"], span["quoted_text"]
            if (
                type(start) is not int
                or type(end) is not int
                or start < 0
                or end <= start
                or end > len(prompt_bytes)
                or not isinstance(quoted, str)
                or span["source_prompt_sha256"] != prompt_sha256
            ):
                raise ContractCleaningError("contract evidence byte coordinates are invalid")
            try:
                actual = prompt_bytes[start:end].decode("utf-8")
            except UnicodeDecodeError:
                raise ContractCleaningError("contract evidence splits a UTF-8 sequence") from None
            if (
                actual != quoted
                or span["span_sha256"]
                != hashlib.sha256(quoted.encode("utf-8")).hexdigest()
            ):
                raise ContractCleaningError("contract evidence is not an exact prompt span")


def _final_readiness_row(
    old: Mapping[str, Any], disposition: str, contract_id: str
) -> dict[str, Any]:
    quality_gate = "PASSED" if disposition == "QUALITY_INCLUDED" else "EXCLUDED"
    action_input = {
        "quality_gate": quality_gate,
        "quality_disposition": disposition,
        "scope_status": old["scope_status"],
        "mechanism_registration_status": old["mechanism_registration_status"],
        "binding_status": old["binding_status"],
        "oracle_status": old["oracle_status"],
        "runtime_status": old["runtime_status"],
        "functional_measurement_status": old["functional_measurement_status"],
        "independent_quality_review_status": "NOT_REQUIRED_OR_COMPLETE",
    }
    summary, workstream, action, evidence = _readiness_action(action_input)
    coordinates = [workstream, str(old.get("language")), str(old.get("primary_cwe"))]
    core = {
        **{
            key: value
            for key, value in old.items()
            if key
            not in {
                "schema_version",
                "readiness_record_sha256",
                "quality_gate",
                "quality_disposition",
                "independent_quality_review_status",
                "readiness_summary_status",
                "workstream",
                "work_group_id",
                "grouping_coordinates",
                "action_status",
                "primary_next_action",
                "required_evidence",
                "contract_id",
            }
        },
        "schema_version": "readiness-work-item-5.0",
        **action_input,
        "readiness_summary_status": summary,
        "workstream": workstream,
        "work_group_id": content_id("readiness_work_group_", coordinates),
        "grouping_coordinates": coordinates,
        "action_status": {
            "QUALITY_EXCLUDED": "CLOSED_EXCLUDED",
            "TECHNICALLY_READY_PENDING_METHOD_FREEZE": "WAITING_METHOD_FREEZE",
        }.get(summary, "OPEN"),
        "primary_next_action": action,
        "required_evidence": evidence,
        "contract_id": contract_id,
    }
    return {**core, "readiness_record_sha256": content_hash(core)}


def _write_final_data_bundle(
    root: Path,
    artifacts: Mapping[str, Sequence[Mapping[str, Any]]],
    report: Mapping[str, Any],
) -> None:
    if root.exists():
        raise FileExistsError(root)
    if set(artifacts) != _FINAL_JSONL_FILES:
        raise ContractCleaningError("final data artifact set is incomplete")
    root.mkdir(parents=True)
    descriptors = {}
    for name, values in sorted(artifacts.items()):
        rows = list(values)
        payload = "".join(canonical_json(row) + "\n" for row in rows).encode("utf-8")
        (root / name).write_bytes(payload)
        descriptors[name] = {
            "format": "canonical-jsonl",
            "record_count": len(rows),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
    report_payload = (canonical_json(report) + "\n").encode("utf-8")
    (root / "report.json").write_bytes(report_payload)
    descriptors["report.json"] = {
        "format": "canonical-json",
        "sha256": hashlib.sha256(report_payload).hexdigest(),
    }
    manifest = {
        "schema_version": "5.0",
        "artifact_kind": "reviewer_task_unit_dataset",
        "files": descriptors,
    }
    (root / "manifest.json").write_bytes(
        (canonical_json(manifest) + "\n").encode("utf-8")
    )


def _canonical_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = path.read_bytes()
        value = json.loads(payload)
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ContractCleaningError(f"{label} is unreadable") from None
    if not isinstance(value, dict) or payload != (canonical_json(value) + "\n").encode("utf-8"):
        raise ContractCleaningError(f"{label} is not canonical JSON")
    return value


def _contract_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    return {key: row[key] for key in ("resolution_status", "entrypoint", *_CONTENT_FIELDS)}


def _proposal_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        **_contract_payload(row),
        "content_evidence": row["content_evidence"],
        "producer_source_assessment": row["producer_source_assessment"],
    }


def _item_chars(item: dict[str, Any]) -> int:
    return len(item["source_prompt"]) + len(json.dumps(item, ensure_ascii=False))


def _evidence_request(batch: Sequence[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "request_kind": "blind_contract_evidence_backfill",
        "arms_outcomes_roles_included": False,
        "tasks": [
            {
                "item_index": index,
                "language": item["language"],
                "source_prompt": item["source_prompt"],
                "immutable_contract": item["old_contract"],
                "evidence_targets": _evidence_targets(item["old_contract"]),
            }
            for index, item in enumerate(batch, start=1)
        ],
    }


def _repair_request(batch: Sequence[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "request_kind": "blind_functional_contract_semantic_repair",
        "arms_outcomes_roles_included": False,
        "tasks": [
            {
                "item_index": index,
                "language": item["language"],
                "source_prompt": item["source_prompt"],
                "previous_contract": item["old_contract"],
                "previous_review_issue_codes": item["old_review"]["issue_codes"],
                "previous_remaining_deterministic_issue_codes": item["old_review"][
                    "remaining_deterministic_issue_codes"
                ],
            }
            for index, item in enumerate(batch, start=1)
        ],
    }


def _review_request(batch: Sequence[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "request_kind": "independent_blind_contract_content_review",
        "arms_outcomes_roles_included": False,
        "tasks": [
            {
                "item_index": index,
                "language": item["language"],
                "source_prompt": item["source_prompt"],
                "proposed_contract": item["contract"],
            }
            for index, item in enumerate(batch, start=1)
        ],
    }


def _parse_evidence_backfill(
    raw: bytes, batch: Sequence[dict[str, Any]]
) -> list[dict[str, Any]]:
    rows = _evidence_response_rows(raw, batch)
    required = {"item_index", "binding_status", "evidence_bindings", "reason"}
    frozen = []
    for row, item in zip(rows, batch, strict=True):
        if set(row) != required or row["binding_status"] not in {"bound", "needs_repair"}:
            raise ContractCleaningError("evidence backfill response is malformed")
        normalized_reason = _normalize_reason(row["reason"])
        evidence = row["evidence_bindings"]
        if row["binding_status"] == "bound":
            try:
                evidence = _normalize_evidence_bindings(
                    evidence,
                    item["old_contract"],
                    item["source_prompt"],
                    item["source_prompt_sha256"],
                )
                frozen_status = "bound"
                reason = normalized_reason
            except ContractCleaningError:
                evidence = None
                frozen_status = "needs_repair"
                reason = "Deterministic validation rejected incomplete or non-literal evidence."
        elif evidence is not None:
            raise ContractCleaningError("unbound contract must not carry evidence")
        else:
            frozen_status = "needs_repair"
            reason = normalized_reason
        frozen.append(
            {
                "task_unit_id": item["task_unit_id"],
                "binding_status": frozen_status,
                "model_binding_status": row["binding_status"],
                "content_evidence": evidence,
                "reason": reason,
            }
        )
    return frozen


def _evidence_response_rows(
    raw: bytes, batch: Sequence[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Project only an exact single-task echo of the supplied target list."""

    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError):
        raise ContractCleaningError("model response is not JSON") from None
    if not isinstance(value, dict) or set(value) != {"items"}:
        raise ContractCleaningError("model response top-level fields are invalid")
    raw_rows = value["items"]
    if not isinstance(raw_rows, list) or any(not isinstance(row, dict) for row in raw_rows):
        raise ContractCleaningError("model response item binding is invalid")
    if len(batch) == 1:
        target_echoes = [
            row for row in raw_rows if set(row) == {"target_id", "value"}
        ]
        if target_echoes:
            if target_echoes != _evidence_targets(batch[0]["old_contract"]):
                raise ContractCleaningError("evidence target echo differs from the request")
            raw_rows = [row for row in raw_rows if set(row) != {"target_id", "value"}]
    return _response_rows(
        canonical_json({"items": raw_rows}).encode("utf-8"), "items", len(batch)
    )


def _parse_semantic_repairs(
    raw: bytes, batch: Sequence[dict[str, Any]]
) -> list[dict[str, Any]]:
    rows = _response_rows(raw, "items", len(batch))
    required = {
        "item_index",
        "resolution_status",
        "entrypoint",
        *_CONTENT_FIELDS,
        "evidence_bindings",
        "source_specification_assessment",
        "repair_category",
        "reason",
    }
    frozen = []
    for row, item in zip(rows, batch, strict=True):
        if (
            set(row) != required
            or row["resolution_status"] not in {"resolved", "ambiguous", "unsupported"}
            or row["source_specification_assessment"] not in _SOURCE_ASSESSMENTS
            or row["repair_category"] not in _REPAIR_CATEGORIES - {"EVIDENCE_BACKFILL_ONLY"}
        ):
            raise ContractCleaningError("semantic repair response is malformed")
        contract = _validate_contract_values(row)
        evidence = _normalize_evidence_bindings(
            row["evidence_bindings"],
            contract,
            item["source_prompt"],
            item["source_prompt_sha256"],
        )
        normalized_reason = _normalize_reason(row["reason"])
        frozen.append(
            {
                "task_unit_id": item["task_unit_id"],
                **contract,
                "content_evidence": evidence,
                "source_specification_assessment": row["source_specification_assessment"],
                "repair_category": row["repair_category"],
                "reason": normalized_reason,
            }
        )
    return frozen


def _parse_contract_repairs(
    raw: bytes, batch: Sequence[dict[str, Any]]
) -> list[dict[str, Any]]:
    rows = _response_rows(raw, "items", len(batch))
    required = {
        "item_index",
        "resolution_status",
        "entrypoint",
        *_CONTENT_FIELDS,
        "source_specification_assessment",
        "repair_category",
        "reason",
    }
    frozen = []
    for row, item in zip(rows, batch, strict=True):
        keys = set(row)
        discarded_evidence = keys == required | {"evidence_bindings"}
        if (
            frozenset(keys)
            not in {frozenset(required), frozenset(required | {"evidence_bindings"})}
            or row["resolution_status"] not in {"resolved", "ambiguous", "unsupported"}
            or row["source_specification_assessment"] not in _SOURCE_ASSESSMENTS
            or row["repair_category"] not in _REPAIR_CATEGORIES - {"EVIDENCE_BACKFILL_ONLY"}
        ):
            raise ContractCleaningError("semantic contract repair response is malformed")
        frozen.append(
            {
                "task_unit_id": item["task_unit_id"],
                **_validate_contract_values(row),
                "source_specification_assessment": row[
                    "source_specification_assessment"
                ],
                "repair_category": row["repair_category"],
                "reason": _normalize_reason(row["reason"]),
                "discarded_out_of_scope_evidence": discarded_evidence,
            }
        )
    return frozen


def _parse_content_reviews(
    raw: bytes, batch: Sequence[dict[str, Any]]
) -> list[dict[str, Any]]:
    rows = _response_rows(raw, "reviews", len(batch))
    required = {
        "item_index",
        "contract_status",
        "evidence_status",
        "source_specification_disposition",
        "issue_codes",
        "repair_category",
        "reason",
    }
    frozen = []
    for row, item in zip(rows, batch, strict=True):
        issues = row.get("issue_codes")
        if (
            set(row) != required
            or row["contract_status"] not in {"faithful", "faulty", "uncertain"}
            or row["evidence_status"] not in {"supported", "unsupported"}
            or row["source_specification_disposition"] not in _SOURCE_ASSESSMENTS
            or row["repair_category"] not in _REPAIR_CATEGORIES
            or not isinstance(issues, list)
            or not 1 <= len(issues) <= 6
            or len(set(issues)) != len(issues)
            or any(issue not in _REVIEW_ISSUES for issue in issues)
            or (
                (row["contract_status"] == "faithful" and row["evidence_status"] == "supported")
                != (issues == ["none"])
            )
        ):
            raise ContractCleaningError("contract content review response is malformed")
        normalized_reason = _normalize_reason(row["reason"])
        frozen.append(
            {
                "task_unit_id": item["task_unit_id"],
                **{
                    key: (normalized_reason if key == "reason" else value)
                    for key, value in row.items()
                    if key != "item_index"
                },
            }
        )
    return frozen


def _response_rows(raw: bytes, field: str, expected: int) -> list[dict[str, Any]]:
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError):
        raise ContractCleaningError("model response is not JSON") from None
    if not isinstance(value, dict) or set(value) != {field}:
        raise ContractCleaningError("model response top-level fields are invalid")
    rows = value[field]
    if not isinstance(rows, list) or not rows or len(rows) > expected * 2 or any(
        not isinstance(row, dict)
        or type(row.get("item_index")) is not int
        or not 1 <= row["item_index"] <= expected
        for row in rows
    ):
        raise ContractCleaningError("model response item binding is invalid")
    by_index = {row["item_index"]: row for row in rows}
    if set(by_index) != set(range(1, expected + 1)):
        raise ContractCleaningError("model response item binding is incomplete")
    return [by_index[index] for index in range(1, expected + 1)]


def _validate_contract_values(row: Mapping[str, Any]) -> dict[str, Any]:
    entrypoint = row.get("entrypoint")
    if entrypoint is not None and (not isinstance(entrypoint, str) or not entrypoint.strip()):
        raise ContractCleaningError("contract entrypoint is invalid")
    result: dict[str, Any] = {
        "resolution_status": row["resolution_status"],
        "entrypoint": entrypoint,
    }
    for field in _CONTENT_FIELDS:
        values = row.get(field)
        if (
            not isinstance(values, list)
            or len(values) > 32
            or any(not isinstance(value, str) or not value.strip() for value in values)
        ):
            raise ContractCleaningError(f"contract {field} is invalid")
        result[field] = values
    if row["resolution_status"] == "resolved" and not result["requirements"]:
        raise ContractCleaningError("resolved contract must contain a requirement")
    return result


def _evidence_targets(contract: Mapping[str, Any]) -> list[dict[str, str]]:
    targets = []
    if contract["entrypoint"] is not None:
        targets.append({"target_id": "entrypoint", "value": contract["entrypoint"]})
    for field in _CONTENT_FIELDS:
        targets.extend(
            {"target_id": f"{field}:{index}", "value": value}
            for index, value in enumerate(contract[field], start=1)
        )
    return targets


def _normalize_evidence_bindings(
    raw: Any,
    contract: Mapping[str, Any],
    prompt: str,
    source_prompt_sha256: str,
) -> dict[str, Any]:
    targets = _evidence_targets(contract)
    if (
        not isinstance(raw, list)
        or len(raw) != len(targets)
        or any(not isinstance(binding, dict) for binding in raw)
    ):
        raise ContractCleaningError("content evidence target count is invalid")
    expected_ids = [target["target_id"] for target in targets]
    if [binding.get("target_id") for binding in raw] != expected_ids:
        raise ContractCleaningError("content evidence target identities are invalid")
    normalized_by_id = {}
    for binding in raw:
        if set(binding) != {"target_id", "spans"}:
            raise ContractCleaningError("content evidence binding is malformed")
        normalized_by_id[binding["target_id"]] = _normalize_span_group(
            binding["spans"], prompt, source_prompt_sha256
        )
    frozen: dict[str, Any] = {
        "offset_basis": "utf8_bytes_of_exact_natural_prompt_v1",
        "entrypoint": normalized_by_id.get("entrypoint", []),
    }
    for field in _CONTENT_FIELDS:
        frozen[field] = [
            normalized_by_id[f"{field}:{index}"]
            for index in range(1, len(contract[field]) + 1)
        ]
    return frozen


def _normalize_span_group(
    group: Any, prompt: str, source_prompt_sha256: str
) -> list[dict[str, Any]]:
    if not isinstance(group, list) or not group:
        raise ContractCleaningError("every non-empty contract value needs source evidence")
    frozen = []
    for span in group:
        if (
            not isinstance(span, dict)
            or set(span) != {"evidence_text", "evidence_occurrence"}
            or not isinstance(span["evidence_text"], str)
            or not span["evidence_text"]
            or type(span["evidence_occurrence"]) is not int
            or span["evidence_occurrence"] <= 0
        ):
            raise ContractCleaningError("source evidence span is malformed")
        start_character = _occurrence_start(
            prompt, span["evidence_text"], span["evidence_occurrence"]
        )
        if start_character is None:
            raise ContractCleaningError("source evidence is not an exact prompt span")
        literal = span["evidence_text"]
        start_byte = len(prompt[:start_character].encode("utf-8"))
        end_byte = start_byte + len(literal.encode("utf-8"))
        frozen.append(
            {
                "source_prompt_sha256": source_prompt_sha256,
                "start_byte": start_byte,
                "end_byte": end_byte,
                "quoted_text": literal,
                "span_sha256": hashlib.sha256(literal.encode("utf-8")).hexdigest(),
            }
        )
    return frozen


def _occurrence_start(prompt: str, literal: str, occurrence: int) -> int | None:
    start = 0
    found = -1
    for _ in range(occurrence):
        found = prompt.find(literal, start)
        if found < 0:
            return None
        start = found + len(literal)
    return found


def _normalize_reason(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractCleaningError("curation reason is invalid")
    return value[:2000]


def _unique_results(rows: Sequence[dict[str, Any]], label: str) -> dict[str, dict[str, Any]]:
    result = {}
    for row in rows:
        task_id = row.get("task_unit_id")
        if not isinstance(task_id, str) or not task_id or task_id in result:
            raise ContractCleaningError(f"{label} identities are invalid")
        result[task_id] = row
    return result


def _evidence_span_count(evidence: Mapping[str, Any]) -> int:
    return len(evidence["entrypoint"]) + sum(
        len(group) for field in _CONTENT_FIELDS for group in evidence[field]
    )


def _terminal_quality(review: Mapping[str, Any]) -> str | None:
    if review["contract_status"] != "faithful" or review["evidence_status"] != "supported":
        return None
    return {
        "sufficient": "QUALITY_INCLUDED",
        "insufficient": "QUALITY_EXCLUDED_INSUFFICIENT_SPECIFICATION",
        "defect": "QUALITY_EXCLUDED_SOURCE_DEFECT",
        "uncertain": None,
    }[review["source_specification_disposition"]]


def _proposal_progress(
    total: int,
    evidence_count: int,
    repair_count: int,
    evidence_results: Sequence[dict[str, Any]],
    repair_results: Sequence[dict[str, Any]],
    complete: bool,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "status": "CONTRACT_CONTENT_PROPOSALS_COMPLETE" if complete else "CONTRACT_CONTENT_PROPOSALS_IN_PROGRESS",
        "task_unit_count": total,
        "evidence_item_count": evidence_count,
        "repair_item_count": repair_count,
        "completed_evidence_item_count": len(evidence_results),
        "completed_repair_item_count": len(repair_results),
        "complete": complete,
    }


__all__ = [
    "ContractCleaningError",
    "adjudicate_unbound_repaired_contract_evidence",
    "assemble_contract_content_proposals",
    "finalize_contract_content_data",
    "freeze_future_evaluation_reservation",
    "run_contract_content_proposals",
    "run_contract_content_review",
    "run_repaired_contract_evidence",
    "run_single_task_semantic_repairs",
    "verify_contract_content_data",
]

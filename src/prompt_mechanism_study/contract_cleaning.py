"""Outcome-blind content cleaning for the reviewer task-unit data foundation."""

from __future__ import annotations

import hashlib
import json
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
from prompt_mechanism_study.functional_judge import bailian_complete
from prompt_mechanism_study.records import canonical_value, content_hash, content_id
from prompt_mechanism_study.task_unit_data import (
    _canonical_jsonl,
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
_EVIDENCE_FIELDS = ("entrypoint", *_CONTENT_FIELDS)
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
    repair_items = sorted(
        initial_repair_items
        + [item for item in evidence_items if item["task_unit_id"] in escalated_ids],
        key=lambda item: item["task_unit_id"],
    )
    repair_results, repair_complete, repair_plan = _run_stage(
        repository_root,
        root / "repair",
        repair_items,
        prompt_name="contract-semantic-repair-v1.txt",
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
) -> tuple[list[dict[str, Any]], bool, dict[str, Any]]:
    evaluator, prompt, policy = _policy(repository_root, prompt_name, config_name)
    batches = _batches(items, "task_unit_id", _BATCH_ITEMS, _item_chars)
    plan = {
        **base_identity,
        "stage": stage,
        "batch_item_limit": _BATCH_ITEMS,
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
        provider,
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
        "max_attempts": 1,
    }
    return evaluator, prompt, identity


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


def _manifest_digest(root: Path) -> str:
    return hashlib.sha256((root / "manifest.json").read_bytes()).hexdigest()


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
    rows = _response_rows(raw, "items", len(batch))
    required = {"item_index", "binding_status", "content_evidence", "reason"}
    frozen = []
    for row, item in zip(rows, batch, strict=True):
        if set(row) != required or row["binding_status"] not in {"bound", "needs_repair"}:
            raise ContractCleaningError("evidence backfill response is malformed")
        _bounded_reason(row["reason"])
        evidence = row["content_evidence"]
        if row["binding_status"] == "bound":
            evidence = _normalize_content_evidence(
                evidence,
                item["old_contract"],
                item["source_prompt"],
                item["source_prompt_sha256"],
            )
        elif evidence is not None:
            raise ContractCleaningError("unbound contract must not carry evidence")
        frozen.append(
            {
                "task_unit_id": item["task_unit_id"],
                "binding_status": row["binding_status"],
                "content_evidence": evidence,
                "reason": row["reason"],
            }
        )
    return frozen


def _parse_semantic_repairs(
    raw: bytes, batch: Sequence[dict[str, Any]]
) -> list[dict[str, Any]]:
    rows = _response_rows(raw, "items", len(batch))
    required = {
        "item_index",
        "resolution_status",
        "entrypoint",
        *_CONTENT_FIELDS,
        "content_evidence",
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
        evidence = _normalize_content_evidence(
            row["content_evidence"],
            contract,
            item["source_prompt"],
            item["source_prompt_sha256"],
        )
        _bounded_reason(row["reason"])
        frozen.append(
            {
                "task_unit_id": item["task_unit_id"],
                **contract,
                "content_evidence": evidence,
                "source_specification_assessment": row["source_specification_assessment"],
                "repair_category": row["repair_category"],
                "reason": row["reason"],
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
        _bounded_reason(row["reason"])
        frozen.append({"task_unit_id": item["task_unit_id"], **{k: v for k, v in row.items() if k != "item_index"}})
    return frozen


def _response_rows(raw: bytes, field: str, expected: int) -> list[dict[str, Any]]:
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError):
        raise ContractCleaningError("model response is not JSON") from None
    if not isinstance(value, dict) or set(value) != {field}:
        raise ContractCleaningError("model response top-level fields are invalid")
    rows = value[field]
    if (
        not isinstance(rows, list)
        or len(rows) != expected
        or any(not isinstance(row, dict) for row in rows)
        or [row.get("item_index") for row in rows] != list(range(1, expected + 1))
    ):
        raise ContractCleaningError("model response item binding is invalid")
    return rows


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


def _normalize_content_evidence(
    raw: Any,
    contract: Mapping[str, Any],
    prompt: str,
    source_prompt_sha256: str,
) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != set(_EVIDENCE_FIELDS):
        raise ContractCleaningError("content evidence fields are invalid")
    frozen: dict[str, Any] = {"offset_basis": "utf8_bytes_of_exact_natural_prompt_v1"}
    entrypoint_spans = raw["entrypoint"]
    if contract["entrypoint"] is None:
        if entrypoint_spans != []:
            raise ContractCleaningError("null entrypoint must not carry evidence")
        frozen["entrypoint"] = []
    else:
        frozen["entrypoint"] = _normalize_span_group(
            entrypoint_spans, prompt, source_prompt_sha256
        )
    for field in _CONTENT_FIELDS:
        groups = raw[field]
        if not isinstance(groups, list) or len(groups) != len(contract[field]):
            raise ContractCleaningError(f"content evidence does not align with {field}")
        frozen[field] = [
            _normalize_span_group(group, prompt, source_prompt_sha256) for group in groups
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


def _bounded_reason(value: Any) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > 2000:
        raise ContractCleaningError("curation reason is invalid")


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
    "freeze_future_evaluation_reservation",
    "run_contract_content_proposals",
    "run_contract_content_review",
]

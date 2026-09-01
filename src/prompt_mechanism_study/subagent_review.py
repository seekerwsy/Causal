"""Frozen blind review packets and decisions for the task-unit data foundation."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from prompt_mechanism_study.artifact_io import (
    bundle_digest,
    read_json,
    verify_bundle,
    write_bundle,
)
from prompt_mechanism_study.contract_cleaning import (
    ContractCleaningError,
    _base_population,
    _manifest_digest,
    _parse_content_reviews,
    _proposal_payload,
    _terminal_quality,
    _unique_by,
)
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.task_unit_data import verify_task_unit_data

_SLOTS = ("reviewer-a", "reviewer-b", "reviewer-c")
_PACKET_ITEMS = 25
_DECISION_FIELDS = {
    "task_unit_id",
    "contract_status",
    "evidence_status",
    "source_specification_disposition",
    "issue_codes",
    "repair_category",
    "reason",
}


def prepare_subagent_contract_reviews(
    repository_root: Path,
    base_bundle: Path,
    proposals_root: Path,
    output: Path,
    *,
    producer_commit: str,
) -> dict[str, Any]:
    """Freeze two blind reviewer assignments and inspectable work packets per task."""

    if not producer_commit or any(character.isspace() for character in producer_commit):
        raise ValueError("producer_commit must be one non-empty token")
    base = base_bundle.resolve()
    proposals = proposals_root.resolve()
    verify_task_unit_data(base)
    verify_bundle(proposals)
    tasks, _, _ = _base_population(base)
    proposed = _unique_by(
        read_json(proposals / "proposed-contracts.json"),
        "task_unit_id",
        "proposed contracts",
    )
    if set(tasks) != set(proposed):
        raise ContractCleaningError("proposal population differs from the base task population")
    prompt_path = repository_root.resolve() / "data/dataset-curation/contract-content-review-v1.txt"
    prompt = prompt_path.read_text(encoding="utf-8").strip()
    if not prompt:
        raise ContractCleaningError("subagent review prompt is empty")

    assignments = []
    by_slot: dict[str, list[dict[str, Any]]] = {slot: [] for slot in _SLOTS}
    for task_id in sorted(tasks):
        primary_index = int(hashlib.sha256(f"primary:{task_id}".encode()).hexdigest(), 16) % 3
        primary = _SLOTS[primary_index]
        secondary = _SLOTS[(primary_index + 1) % 3]
        adjudicator = _SLOTS[(primary_index + 2) % 3]
        assignments.append(
            {
                "task_unit_id": task_id,
                "primary_reviewer": primary,
                "secondary_reviewer": secondary,
                "blind_adjudicator": adjudicator,
            }
        )
        task = tasks[task_id]
        item = {
            "task_unit_id": task_id,
            "language": task["declared_execution_context"]["language"],
            "source_prompt": task["model_visible_input"]["natural_prompt"],
            "proposed_contract": _proposal_payload(proposed[task_id]),
        }
        by_slot[primary].append(item)
        by_slot[secondary].append(item)

    artifacts: dict[str, Any] = {}
    packet_index = []
    for slot in _SLOTS:
        items = sorted(by_slot[slot], key=lambda item: item["task_unit_id"])
        for number, start in enumerate(range(0, len(items), _PACKET_ITEMS), start=1):
            packet_items = items[start : start + _PACKET_ITEMS]
            packet_id = f"{slot}-{number:04d}"
            file_name = f"{packet_id}.json"
            packet = {
                "schema_version": "subagent-contract-review-packet-1.0",
                "packet_id": packet_id,
                "reviewer_slot": slot,
                "blindness": {
                    "arms_outcomes_roles_withheld": True,
                    "cwe_readiness_oracles_withheld": True,
                    "other_reviewer_decisions_withheld": True,
                },
                "protocol_prompt_sha256": hashlib.sha256(prompt_path.read_bytes()).hexdigest(),
                "tasks": packet_items,
            }
            artifacts[file_name] = packet
            packet_index.append(
                {
                    "packet_id": packet_id,
                    "file_name": file_name,
                    "reviewer_slot": slot,
                    "task_unit_ids": [item["task_unit_id"] for item in packet_items],
                }
            )
    plan = {
        "schema_version": "subagent-contract-review-plan-1.0",
        "protocol_id": "dual_blind_subagent_review_with_third_adjudication_v1",
        "reviewer_backend": "codex_collaboration_subagent_inherited_model_unseeded",
        "replay_boundary": "frozen_packets_decisions_and_merger_not_future_model_sampling",
        "producer_commit": producer_commit,
        "base_bundle_sha256": _manifest_digest(base),
        "proposals_bundle_sha256": bundle_digest(proposals),
        "protocol_prompt_sha256": hashlib.sha256(prompt_path.read_bytes()).hexdigest(),
        "task_unit_count": len(tasks),
        "reviewer_slots": list(_SLOTS),
        "packet_item_limit": _PACKET_ITEMS,
        "assignments": assignments,
        "packets": packet_index,
        "decision_fields": sorted(_DECISION_FIELDS),
        "decision_rule": {
            "agreement_fields": [
                "contract_status",
                "evidence_status",
                "source_specification_disposition",
            ],
            "on_agreement": "use_primary_review_with_deterministic_diagnostics",
            "on_disagreement": "blind_third_review_is_final",
        },
        "arms_or_outcomes_used": False,
        "formal_roles_used": False,
    }
    artifacts["plan.json"] = plan
    write_bundle(output.resolve(), artifacts)
    return {
        "status": "SUBAGENT_CONTRACT_REVIEW_PACKETS_FROZEN",
        "task_unit_count": len(tasks),
        "review_assignment_count": sum(len(values) for values in by_slot.values()),
        "packet_count": len(packet_index),
        "packets_by_reviewer": dict(
            sorted(Counter(item["reviewer_slot"] for item in packet_index).items())
        ),
        "bundle_sha256": bundle_digest(output.resolve()),
        "arms_or_outcomes_used": False,
    }


def seal_initial_subagent_contract_reviews(
    packets_root: Path,
    decisions_root: Path,
    output: Path,
) -> dict[str, Any]:
    """Validate all dual reviews and freeze blind adjudication packets for disagreements."""

    packets = packets_root.resolve()
    verify_bundle(packets)
    plan = read_json(packets / "plan.json")
    assignments = _assignment_map(plan)
    decisions = _load_slot_decisions(packets, decisions_root.resolve(), plan)
    disagreements = []
    final_agreements = []
    adjudication_by_slot: dict[str, list[dict[str, Any]]] = {slot: [] for slot in _SLOTS}
    task_by_id = {
        item["task_unit_id"]: item
        for packet in plan["packets"]
        for item in read_json(packets / packet["file_name"])["tasks"]
    }
    if set(task_by_id) != set(assignments):
        raise ContractCleaningError("subagent packet population differs from the review plan")
    for task_id in sorted(assignments):
        assignment = assignments[task_id]
        primary = decisions[assignment["primary_reviewer"]][task_id]
        secondary = decisions[assignment["secondary_reviewer"]][task_id]
        if _review_tuple(primary) == _review_tuple(secondary):
            final_agreements.append(primary)
            continue
        disagreements.append(
            {
                "task_unit_id": task_id,
                "primary_reviewer": assignment["primary_reviewer"],
                "secondary_reviewer": assignment["secondary_reviewer"],
                "blind_adjudicator": assignment["blind_adjudicator"],
                "primary_decision_sha256": content_hash(primary),
                "secondary_decision_sha256": content_hash(secondary),
            }
        )
        adjudication_by_slot[assignment["blind_adjudicator"]].append(task_by_id[task_id])

    artifacts: dict[str, Any] = {
        "initial-decisions.json": [
            {"reviewer_slot": slot, **row}
            for slot in _SLOTS
            for row in sorted(decisions[slot].values(), key=lambda item: item["task_unit_id"])
        ],
        "agreements.json": final_agreements,
        "disagreements.json": disagreements,
        "source-plan.json": plan,
    }
    adjudication_index = []
    for slot in _SLOTS:
        items = sorted(adjudication_by_slot[slot], key=lambda item: item["task_unit_id"])
        for number, start in enumerate(range(0, len(items), _PACKET_ITEMS), start=1):
            packet_items = items[start : start + _PACKET_ITEMS]
            packet_id = f"{slot}-adjudication-{number:04d}"
            file_name = f"{packet_id}.json"
            artifacts[file_name] = {
                "schema_version": "subagent-contract-review-packet-1.0",
                "packet_id": packet_id,
                "reviewer_slot": slot,
                "blindness": {
                    "arms_outcomes_roles_withheld": True,
                    "cwe_readiness_oracles_withheld": True,
                    "other_reviewer_decisions_withheld": True,
                },
                "protocol_prompt_sha256": plan["protocol_prompt_sha256"],
                "tasks": packet_items,
            }
            adjudication_index.append(
                {
                    "packet_id": packet_id,
                    "file_name": file_name,
                    "reviewer_slot": slot,
                    "task_unit_ids": [item["task_unit_id"] for item in packet_items],
                }
            )
    artifacts["adjudication-plan.json"] = {
        "schema_version": "subagent-contract-adjudication-plan-1.0",
        "protocol_prompt_sha256": plan["protocol_prompt_sha256"],
        "disagreement_count": len(disagreements),
        "packets": adjudication_index,
        "arms_or_outcomes_used": False,
    }
    write_bundle(output.resolve(), artifacts)
    return {
        "status": "SUBAGENT_INITIAL_REVIEWS_FROZEN",
        "task_unit_count": len(assignments),
        "agreement_count": len(final_agreements),
        "disagreement_count": len(disagreements),
        "adjudication_packet_count": len(adjudication_index),
        "bundle_sha256": bundle_digest(output.resolve()),
    }


def finalize_subagent_contract_reviews(
    initial_root: Path,
    adjudication_decisions_root: Path,
    proposals_root: Path,
    output: Path,
) -> dict[str, Any]:
    """Freeze one independent terminal-or-repair decision for every proposed contract."""

    initial = initial_root.resolve()
    verify_bundle(initial)
    plan = read_json(initial / "source-plan.json")
    proposals = proposals_root.resolve()
    verify_bundle(proposals)
    proposed = _unique_by(
        read_json(proposals / "proposed-contracts.json"),
        "task_unit_id",
        "proposed contracts",
    )
    agreements = _unique_by(read_json(initial / "agreements.json"), "task_unit_id", "agreements")
    disagreements = _unique_by(
        read_json(initial / "disagreements.json"), "task_unit_id", "disagreements"
    )
    adjudication_plan = read_json(initial / "adjudication-plan.json")
    adjudications = _load_adjudications(
        initial, adjudication_decisions_root.resolve(), adjudication_plan
    )
    if set(agreements) | set(disagreements) != set(proposed) or set(agreements) & set(
        disagreements
    ):
        raise ContractCleaningError("subagent review populations are invalid")
    if set(adjudications) != set(disagreements):
        raise ContractCleaningError("subagent adjudication population is incomplete")

    frozen = []
    for task_id in sorted(proposed):
        decision = agreements.get(task_id, adjudications.get(task_id))
        assert decision is not None
        core = {
            "schema_version": "contract-content-review-1.0",
            "task_unit_id": task_id,
            "contract_id": proposed[task_id]["contract_id"],
            **{key: value for key, value in decision.items() if key != "task_unit_id"},
            "terminal_quality_decision": _terminal_quality(decision),
            "arms_or_outcomes_used": False,
        }
        frozen.append({**core, "contract_content_review_record_sha256": content_hash(core)})
    terminal = sum(row["terminal_quality_decision"] is not None for row in frozen)
    report = {
        "schema_version": "1.0",
        "status": "CONTRACT_CONTENT_REVIEW_FROZEN",
        "review_protocol_id": plan["protocol_id"],
        "task_unit_count": len(frozen),
        "terminal_quality_decision_count": terminal,
        "nonterminal_count": len(frozen) - terminal,
        "dual_review_agreement_count": len(agreements),
        "blind_third_adjudication_count": len(adjudications),
        "contract_status_counts": dict(
            sorted(Counter(row["contract_status"] for row in frozen).items())
        ),
        "evidence_status_counts": dict(
            sorted(Counter(row["evidence_status"] for row in frozen).items())
        ),
        "source_specification_disposition_counts": dict(
            sorted(
                Counter(row["source_specification_disposition"] for row in frozen).items()
            )
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
        "source_plan_sha256": content_hash(plan),
        "initial_review_bundle_sha256": bundle_digest(initial),
        "proposals_bundle_sha256": bundle_digest(proposals),
        "arms_or_outcomes_used": False,
        "formal_roles_used": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(
        output.resolve(),
        {"contract-content-reviews.json": frozen, "report.json": report},
    )
    return report


def _assignment_map(plan: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    if (
        plan.get("schema_version") != "subagent-contract-review-plan-1.0"
        or plan.get("reviewer_slots") != list(_SLOTS)
        or plan.get("arms_or_outcomes_used") is not False
    ):
        raise ContractCleaningError("subagent review plan is invalid")
    assignments = _unique_by(plan["assignments"], "task_unit_id", "review assignments")
    for assignment in assignments.values():
        roles = {
            assignment.get("primary_reviewer"),
            assignment.get("secondary_reviewer"),
            assignment.get("blind_adjudicator"),
        }
        if roles != set(_SLOTS):
            raise ContractCleaningError("subagent review assignment does not separate reviewers")
    return assignments


def _load_slot_decisions(
    packets_root: Path, decisions_root: Path, plan: Mapping[str, Any]
) -> dict[str, dict[str, dict[str, Any]]]:
    result: dict[str, dict[str, dict[str, Any]]] = {slot: {} for slot in _SLOTS}
    expected_files = {packet["packet_id"] + ".json" for packet in plan["packets"]}
    actual_files = {path.name for path in decisions_root.glob("*.json")}
    if actual_files != expected_files:
        raise ContractCleaningError("subagent decision file set is incomplete")
    for packet in plan["packets"]:
        source = read_json(packets_root / packet["file_name"])
        rows = _decision_rows(read_json(decisions_root / f"{packet['packet_id']}.json"))
        expected = {item["task_unit_id"] for item in source["tasks"]}
        values = _unique_by(rows, "task_unit_id", "subagent packet decisions")
        if set(values) != expected:
            raise ContractCleaningError("subagent packet decision identities differ")
        slot = packet["reviewer_slot"]
        overlap = set(result[slot]) & set(values)
        if overlap:
            raise ContractCleaningError("subagent slot reviewed a task twice")
        result[slot].update(values)
    return result


def _load_adjudications(
    initial_root: Path,
    decisions_root: Path,
    plan: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    packets = plan.get("packets")
    if not isinstance(packets, list):
        raise ContractCleaningError("subagent adjudication plan is invalid")
    expected_files = {packet["packet_id"] + ".json" for packet in packets}
    actual_files = {path.name for path in decisions_root.glob("*.json")}
    if actual_files != expected_files:
        raise ContractCleaningError("subagent adjudication file set is incomplete")
    result: dict[str, dict[str, Any]] = {}
    for packet in packets:
        source = read_json(initial_root / packet["file_name"])
        values = _unique_by(
            _decision_rows(read_json(decisions_root / f"{packet['packet_id']}.json")),
            "task_unit_id",
            "subagent adjudications",
        )
        expected = {item["task_unit_id"] for item in source["tasks"]}
        if set(values) != expected or set(result) & set(values):
            raise ContractCleaningError("subagent adjudication identities differ")
        result.update(values)
    return result


def _decision_rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ContractCleaningError("subagent decisions must be a JSON array")
    for row in value:
        if set(row) != _DECISION_FIELDS:
            raise ContractCleaningError("subagent decision fields are invalid")
        raw = json.dumps(
            {
                "reviews": [
                    {"item_index": 1, **{k: v for k, v in row.items() if k != "task_unit_id"}}
                ]
            }
        ).encode()

        item = {"task_unit_id": row["task_unit_id"]}
        normalized = _parse_content_reviews(raw, [item])[0]
        row.clear()
        row.update(normalized)
    return value


def _review_tuple(review: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        review["contract_status"],
        review["evidence_status"],
        review["source_specification_disposition"],
    )


__all__ = [
    "finalize_subagent_contract_reviews",
    "prepare_subagent_contract_reviews",
    "seal_initial_subagent_contract_reviews",
]

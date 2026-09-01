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
    _CONTENT_FIELDS,
    ContractCleaningError,
    _base_population,
    _full_prompt_content_evidence,
    _manifest_digest,
    _parse_contract_repairs,
    _parse_content_reviews,
    _proposal_payload,
    _terminal_quality,
    _unique_by,
)
from prompt_mechanism_study.records import content_hash, content_id
from prompt_mechanism_study.task_unit_data import verify_task_unit_data

_SLOTS = ("reviewer-a", "reviewer-b", "reviewer-c")
_PACKET_ITEMS = 25
_REPAIR_PACKET_ITEMS = 10
_DECISION_FIELDS = {
    "task_unit_id",
    "contract_status",
    "evidence_status",
    "source_specification_disposition",
    "issue_codes",
    "repair_category",
    "reason",
}
_REPAIR_FIELDS = {
    "task_unit_id",
    "resolution_status",
    "entrypoint",
    *_CONTENT_FIELDS,
    "source_specification_assessment",
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
    nonterminal_reviews_root: Path | None = None,
) -> dict[str, Any]:
    """Freeze two blind reviewer assignments and inspectable work packets per task.

    A prior review bundle may select only nonterminal contracts after repair.  The
    selection is frozen in the plan; it never depends on task roles or outcomes.
    """

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
    selected_task_ids = set(tasks)
    selection: dict[str, Any] = {"kind": "full_population"}
    if nonterminal_reviews_root is not None:
        prior_reviews = nonterminal_reviews_root.resolve()
        verify_bundle(prior_reviews)
        prior = _unique_by(
            read_json(prior_reviews / "contract-content-reviews.json"),
            "task_unit_id",
            "prior contract reviews",
        )
        if set(prior) != set(tasks):
            raise ContractCleaningError("prior review population differs from the base tasks")
        selected_task_ids = {
            task_id
            for task_id, review in prior.items()
            if review.get("terminal_quality_decision") is None
        }
        if not selected_task_ids:
            raise ContractCleaningError("prior review bundle has no nonterminal contracts")
        selection = {
            "kind": "prior_nonterminal_contracts",
            "prior_reviews_bundle_sha256": bundle_digest(prior_reviews),
        }
    prompt_path = repository_root.resolve() / "data/dataset-curation/contract-content-review-v1.txt"
    prompt = prompt_path.read_text(encoding="utf-8").strip()
    if not prompt:
        raise ContractCleaningError("subagent review prompt is empty")

    assignments = []
    by_slot: dict[str, list[dict[str, Any]]] = {slot: [] for slot in _SLOTS}
    for task_id in sorted(selected_task_ids):
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
            "source_prompt": task["model_visible_input"]["natural_prompt"],
            "proposed_contract": _blind_proposal_payload(proposed[task_id]),
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
                "schema_version": "subagent-contract-review-packet-1.1",
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
        "schema_version": "subagent-contract-review-plan-1.1",
        "protocol_id": "dual_blind_subagent_review_with_third_adjudication_v2_unanchored",
        "reviewer_backend": "codex_collaboration_subagent_inherited_model_unseeded",
        "replay_boundary": "frozen_packets_decisions_and_merger_not_future_model_sampling",
        "producer_commit": producer_commit,
        "base_bundle_sha256": _manifest_digest(base),
        "proposals_bundle_sha256": bundle_digest(proposals),
        "protocol_prompt_sha256": hashlib.sha256(prompt_path.read_bytes()).hexdigest(),
        "task_unit_count": len(selected_task_ids),
        "selection": selection,
        "reviewer_slots": list(_SLOTS),
        "packet_item_limit": _PACKET_ITEMS,
        "assignments": assignments,
        "packets": packet_index,
        "decision_fields": sorted(_DECISION_FIELDS),
        "review_input_fields": ["task_unit_id", "source_prompt", "proposed_contract"],
        "producer_source_assessment_withheld": True,
        "declared_language_metadata_withheld": True,
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
        "task_unit_count": len(selected_task_ids),
        "review_assignment_count": sum(len(values) for values in by_slot.values()),
        "packet_count": len(packet_index),
        "packets_by_reviewer": dict(
            sorted(Counter(item["reviewer_slot"] for item in packet_index).items())
        ),
        "bundle_sha256": bundle_digest(output.resolve()),
        "arms_or_outcomes_used": False,
    }


def prepare_subagent_contract_repairs(
    repository_root: Path,
    base_bundle: Path,
    proposals_root: Path,
    reviews_root: Path,
    output: Path,
    *,
    producer_commit: str,
) -> dict[str, Any]:
    """Freeze source-only repair packets for every nonterminal contract review."""

    if not producer_commit or any(character.isspace() for character in producer_commit):
        raise ValueError("producer_commit must be one non-empty token")
    base = base_bundle.resolve()
    proposals = proposals_root.resolve()
    reviews = reviews_root.resolve()
    verify_task_unit_data(base)
    verify_bundle(proposals)
    verify_bundle(reviews)
    tasks, _, _ = _base_population(base)
    proposed = _unique_by(
        read_json(proposals / "proposed-contracts.json"),
        "task_unit_id",
        "proposed contracts",
    )
    reviewed = _unique_by(
        read_json(reviews / "contract-content-reviews.json"),
        "task_unit_id",
        "contract reviews",
    )
    if set(tasks) != set(proposed) or set(tasks) != set(reviewed):
        raise ContractCleaningError("repair inputs do not cover the base task population")
    for task_id, review in reviewed.items():
        _validate_review_record_identity(review)
        if review.get("contract_id") != proposed[task_id].get("contract_id"):
            raise ContractCleaningError("repair selection review is stale")
    repair_ids = {
        task_id
        for task_id, review in reviewed.items()
        if review.get("terminal_quality_decision") is None
    }
    if not repair_ids:
        raise ContractCleaningError("contract review has no nonterminal repairs")
    prompt_path = repository_root.resolve() / "data/dataset-curation/contract-semantic-repair-v2.txt"
    if not prompt_path.read_text(encoding="utf-8").strip():
        raise ContractCleaningError("subagent repair prompt is empty")

    by_slot: dict[str, list[dict[str, Any]]] = {slot: [] for slot in _SLOTS}
    assignments = []
    for task_id in sorted(repair_ids):
        slot = _SLOTS[
            int(hashlib.sha256(f"repair:{task_id}".encode()).hexdigest(), 16) % len(_SLOTS)
        ]
        assignments.append({"task_unit_id": task_id, "repair_producer": slot})
        task = tasks[task_id]
        by_slot[slot].append(
            {
                "task_unit_id": task_id,
                "source_prompt": task["model_visible_input"]["natural_prompt"],
                "previous_contract": _proposal_payload(proposed[task_id]),
                "previous_review": {
                    key: reviewed[task_id][key]
                    for key in (
                        "contract_status",
                        "evidence_status",
                        "source_specification_disposition",
                        "issue_codes",
                        "repair_category",
                        "reason",
                    )
                },
            }
        )

    artifacts: dict[str, Any] = {}
    packet_index = []
    for slot in _SLOTS:
        items = sorted(by_slot[slot], key=lambda item: item["task_unit_id"])
        for number, start in enumerate(range(0, len(items), _REPAIR_PACKET_ITEMS), start=1):
            packet_items = items[start : start + _REPAIR_PACKET_ITEMS]
            packet_id = f"{slot}-repair-{number:04d}"
            file_name = f"{packet_id}.json"
            artifacts[file_name] = {
                "schema_version": "subagent-contract-repair-packet-1.0",
                "packet_id": packet_id,
                "repair_producer": slot,
                "blindness": {
                    "arms_outcomes_roles_withheld": True,
                    "cwe_readiness_oracles_withheld": True,
                },
                "protocol_prompt_sha256": hashlib.sha256(prompt_path.read_bytes()).hexdigest(),
                "tasks": packet_items,
            }
            packet_index.append(
                {
                    "packet_id": packet_id,
                    "file_name": file_name,
                    "repair_producer": slot,
                    "task_unit_ids": [item["task_unit_id"] for item in packet_items],
                }
            )
    plan = {
        "schema_version": "subagent-contract-repair-plan-1.0",
        "protocol_id": "source_only_subagent_contract_repair_v1",
        "producer_commit": producer_commit,
        "base_bundle_sha256": _manifest_digest(base),
        "proposals_bundle_sha256": bundle_digest(proposals),
        "reviews_bundle_sha256": bundle_digest(reviews),
        "protocol_prompt_sha256": hashlib.sha256(prompt_path.read_bytes()).hexdigest(),
        "task_unit_count": len(repair_ids),
        "assignments": assignments,
        "packets": packet_index,
        "decision_fields": sorted(_REPAIR_FIELDS),
        "evidence_policy": "whole_prompt_exact_span_pending_independent_semantic_review",
        "arms_or_outcomes_used": False,
        "formal_roles_used": False,
    }
    artifacts["plan.json"] = plan
    write_bundle(output.resolve(), artifacts)
    return {
        "status": "SUBAGENT_CONTRACT_REPAIR_PACKETS_FROZEN",
        "repair_task_unit_count": len(repair_ids),
        "packet_count": len(packet_index),
        "packets_by_producer": dict(
            sorted(Counter(item["repair_producer"] for item in packet_index).items())
        ),
        "bundle_sha256": bundle_digest(output.resolve()),
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
                "schema_version": "subagent-contract-review-packet-1.1",
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
    if plan.get("proposals_bundle_sha256") != bundle_digest(proposals):
        raise ContractCleaningError("reviewed proposal bundle identity has drifted")
    assignments = _assignment_map(plan)
    reviewed_task_ids = set(assignments)
    if not reviewed_task_ids <= set(proposed):
        raise ContractCleaningError("subagent review selection is absent from proposals")
    agreements = _unique_by(read_json(initial / "agreements.json"), "task_unit_id", "agreements")
    disagreements = _unique_by(
        read_json(initial / "disagreements.json"), "task_unit_id", "disagreements"
    )
    adjudication_plan = read_json(initial / "adjudication-plan.json")
    for packet in adjudication_plan.get("packets", []):
        if any(
            assignments[task_id]["blind_adjudicator"] != packet.get("reviewer_slot")
            for task_id in packet.get("task_unit_ids", [])
        ):
            raise ContractCleaningError("adjudication packet reviewer assignment is invalid")
    adjudications = _load_adjudications(
        initial, adjudication_decisions_root.resolve(), adjudication_plan
    )
    if set(agreements) | set(disagreements) != reviewed_task_ids or set(
        agreements
    ) & set(disagreements):
        raise ContractCleaningError("subagent review populations are invalid")
    if set(adjudications) != set(disagreements):
        raise ContractCleaningError("subagent adjudication population is incomplete")

    frozen = []
    for task_id in sorted(reviewed_task_ids):
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


def finalize_subagent_contract_repairs(
    base_bundle: Path,
    proposals_root: Path,
    reviews_root: Path,
    packets_root: Path,
    decisions_root: Path,
    output: Path,
    *,
    producer_commit: str,
) -> dict[str, Any]:
    """Replace only nonterminal proposals with source-only subagent repairs."""

    if not producer_commit or any(character.isspace() for character in producer_commit):
        raise ValueError("producer_commit must be one non-empty token")
    base = base_bundle.resolve()
    proposals = proposals_root.resolve()
    reviews = reviews_root.resolve()
    packets = packets_root.resolve()
    decisions = decisions_root.resolve()
    verify_task_unit_data(base)
    for root in (proposals, reviews, packets):
        verify_bundle(root)
    tasks, _, _ = _base_population(base)
    proposed = _unique_by(
        read_json(proposals / "proposed-contracts.json"),
        "task_unit_id",
        "proposed contracts",
    )
    prior_ledger = _unique_by(
        read_json(proposals / "contract-repair-ledger.json"),
        "task_unit_id",
        "contract repair ledger",
    )
    reviewed = _unique_by(
        read_json(reviews / "contract-content-reviews.json"),
        "task_unit_id",
        "contract reviews",
    )
    plan = read_json(packets / "plan.json")
    if (
        plan.get("schema_version") != "subagent-contract-repair-plan-1.0"
        or plan.get("arms_or_outcomes_used") is not False
        or plan.get("base_bundle_sha256") != _manifest_digest(base)
        or plan.get("proposals_bundle_sha256") != bundle_digest(proposals)
        or plan.get("reviews_bundle_sha256") != bundle_digest(reviews)
        or plan.get("producer_commit") != producer_commit
        or set(tasks) != set(proposed)
        or set(tasks) != set(prior_ledger)
        or set(tasks) != set(reviewed)
    ):
        raise ContractCleaningError("subagent repair inputs are invalid")
    repair_ids = {
        task_id
        for task_id, review in reviewed.items()
        if review.get("terminal_quality_decision") is None
    }
    planned_ids = {row["task_unit_id"] for row in plan.get("assignments", [])}
    if planned_ids != repair_ids:
        raise ContractCleaningError("subagent repair selection is stale")
    expected_files = {packet["packet_id"] + ".json" for packet in plan["packets"]}
    if {path.name for path in decisions.glob("*.json")} != expected_files:
        raise ContractCleaningError("subagent repair decision file set is incomplete")

    repaired: dict[str, dict[str, Any]] = {}
    for packet_row in plan["packets"]:
        packet = read_json(packets / packet_row["file_name"])
        _validate_packet_against_plan(
            packet,
            packet_row,
            protocol_prompt_sha256=plan["protocol_prompt_sha256"],
            slot_field="repair_producer",
        )
        rows = _repair_rows(
            read_json(decisions / f"{packet_row['packet_id']}.json"),
            packet["tasks"],
        )
        values = _unique_by(rows, "task_unit_id", "subagent contract repairs")
        expected = {item["task_unit_id"] for item in packet["tasks"]}
        if set(values) != expected or set(repaired) & set(values):
            raise ContractCleaningError("subagent repair identities differ")
        repaired.update(values)
    if set(repaired) != repair_ids:
        raise ContractCleaningError("subagent repair population is incomplete")

    next_proposals = []
    next_ledger = []
    for task_id in sorted(tasks):
        if task_id not in repaired:
            next_proposals.append(proposed[task_id])
            next_ledger.append(prior_ledger[task_id])
            continue
        repair = repaired[task_id]
        task = tasks[task_id]
        prompt = task["model_visible_input"]["natural_prompt"]
        prompt_sha256 = task["model_visible_input"]["natural_prompt_content_sha256"]
        contract_values = {
            key: repair[key]
            for key in ("resolution_status", "entrypoint", *_CONTENT_FIELDS)
        }
        evidence = _full_prompt_content_evidence(contract_values, prompt, prompt_sha256)
        core = {
            "schema_version": "functional-contract-cleaning-proposal-1.0",
            "task_unit_id": task_id,
            "record_id": task["representative_record_id"],
            "source_prompt_sha256": prompt_sha256,
            **contract_values,
            "content_evidence": evidence,
            "proposal_mode": "SUBAGENT_SEMANTIC_REPAIR",
            "producer_source_assessment": repair["source_specification_assessment"],
            "producer_reason": repair["reason"],
            "arms_or_outcomes_used": False,
        }
        proposal = {**core, "contract_id": content_id("functional_contract_", core)}
        next_proposals.append(proposal)
        old_ledger = prior_ledger[task_id]
        ledger_core = {
            **{
                key: value
                for key, value in old_ledger.items()
                if key != "repair_ledger_record_sha256"
            },
            "schema_version": "contract-repair-ledger-1.1",
            "old_contract_id": proposed[task_id]["contract_id"],
            "repair_category": repair["repair_category"],
            "repair_status": "PROPOSED_PENDING_INDEPENDENT_REVIEW",
            "new_contract_id": proposal["contract_id"],
            "source_specification_disposition": repair[
                "source_specification_assessment"
            ],
            "evidence_binding_status": "full_prompt_pending_review",
            "evidence_adjudication": "FULL_PROMPT_PENDING_INDEPENDENT_REVIEW",
            "review_status": "PENDING",
            "review_issue_codes": [],
            "input_sha256": content_hash(
                {
                    "task_unit_id": task_id,
                    "source_prompt_sha256": prompt_sha256,
                    "old_contract_id": proposed[task_id]["contract_id"],
                    "prior_review_record_sha256": reviewed[task_id][
                        "contract_content_review_record_sha256"
                    ],
                }
            ),
            "output_sha256": content_hash(proposal),
            "producer_commit": producer_commit,
        }
        next_ledger.append(
            {**ledger_core, "repair_ledger_record_sha256": content_hash(ledger_core)}
        )
    report = {
        "schema_version": "1.0",
        "status": "SUBAGENT_CONTRACT_REPAIRS_FROZEN_PENDING_REVIEW",
        "task_unit_count": len(tasks),
        "repaired_contract_count": len(repaired),
        "unchanged_terminal_contract_count": len(tasks) - len(repaired),
        "full_prompt_pending_review_count": len(repaired),
        "base_bundle_sha256": _manifest_digest(base),
        "prior_proposals_bundle_sha256": bundle_digest(proposals),
        "prior_reviews_bundle_sha256": bundle_digest(reviews),
        "repair_packets_bundle_sha256": bundle_digest(packets),
        "producer_commit": producer_commit,
        "arms_or_outcomes_used": False,
        "formal_roles_used": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(
        output.resolve(),
        {
            "proposed-contracts.json": next_proposals,
            "contract-repair-ledger.json": next_ledger,
            "report.json": report,
        },
    )
    return {**report, "bundle_sha256": bundle_digest(output.resolve())}


def merge_subagent_contract_reviews(
    prior_reviews_root: Path,
    revised_reviews_root: Path,
    proposals_root: Path,
    output: Path,
) -> dict[str, Any]:
    """Merge a repaired-contract review subset into the prior full review population."""

    prior_root = prior_reviews_root.resolve()
    revised_root = revised_reviews_root.resolve()
    proposals = proposals_root.resolve()
    for root in (prior_root, revised_root, proposals):
        verify_bundle(root)
    prior = _unique_by(
        read_json(prior_root / "contract-content-reviews.json"),
        "task_unit_id",
        "prior contract reviews",
    )
    revised = _unique_by(
        read_json(revised_root / "contract-content-reviews.json"),
        "task_unit_id",
        "revised contract reviews",
    )
    proposed = _unique_by(
        read_json(proposals / "proposed-contracts.json"),
        "task_unit_id",
        "proposed contracts",
    )
    if set(prior) != set(proposed) or not set(revised) <= set(prior):
        raise ContractCleaningError("review merge populations are invalid")
    for review in (*prior.values(), *revised.values()):
        _validate_review_record_identity(review)
    if any(
        prior[task_id].get("terminal_quality_decision") is not None
        for task_id in revised
    ):
        raise ContractCleaningError("revised reviews may replace only prior nonterminal tasks")

    merged = []
    for task_id in sorted(prior):
        review = revised.get(task_id, prior[task_id])
        if review.get("contract_id") != proposed[task_id].get("contract_id"):
            raise ContractCleaningError("merged review does not bind the current proposal")
        _validate_review_record_identity(review)
        merged.append(review)
    terminal = sum(row["terminal_quality_decision"] is not None for row in merged)
    report = {
        "schema_version": "1.0",
        "status": "CONTRACT_CONTENT_REVIEW_FROZEN",
        "review_protocol_id": "subagent_review_repair_merge_v1",
        "task_unit_count": len(merged),
        "terminal_quality_decision_count": terminal,
        "nonterminal_count": len(merged) - terminal,
        "revised_review_count": len(revised),
        "preserved_review_count": len(merged) - len(revised),
        "contract_status_counts": dict(
            sorted(Counter(row["contract_status"] for row in merged).items())
        ),
        "evidence_status_counts": dict(
            sorted(Counter(row["evidence_status"] for row in merged).items())
        ),
        "source_specification_disposition_counts": dict(
            sorted(
                Counter(row["source_specification_disposition"] for row in merged).items()
            )
        ),
        "quality_disposition_counts": dict(
            sorted(
                Counter(
                    row["terminal_quality_decision"]
                    for row in merged
                    if row["terminal_quality_decision"] is not None
                ).items()
            )
        ),
        "prior_reviews_bundle_sha256": bundle_digest(prior_root),
        "revised_reviews_bundle_sha256": bundle_digest(revised_root),
        "proposals_bundle_sha256": bundle_digest(proposals),
        "arms_or_outcomes_used": False,
        "formal_roles_used": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(
        output.resolve(),
        {"contract-content-reviews.json": merged, "report.json": report},
    )
    return {**report, "bundle_sha256": bundle_digest(output.resolve())}


def _assignment_map(plan: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    if (
        plan.get("schema_version")
        not in {"subagent-contract-review-plan-1.0", "subagent-contract-review-plan-1.1"}
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
        _validate_packet_against_plan(
            source,
            packet,
            protocol_prompt_sha256=plan["protocol_prompt_sha256"],
            slot_field="reviewer_slot",
        )
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
        _validate_packet_against_plan(
            source,
            packet,
            protocol_prompt_sha256=plan["protocol_prompt_sha256"],
            slot_field="reviewer_slot",
        )
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


def _validate_packet_against_plan(
    packet: Mapping[str, Any],
    plan_row: Mapping[str, Any],
    *,
    protocol_prompt_sha256: str,
    slot_field: str,
) -> None:
    tasks = packet.get("tasks")
    if (
        packet.get("packet_id") != plan_row.get("packet_id")
        or packet.get(slot_field) != plan_row.get(slot_field)
        or packet.get("protocol_prompt_sha256") != protocol_prompt_sha256
        or not isinstance(tasks, list)
        or [item.get("task_unit_id") for item in tasks]
        != plan_row.get("task_unit_ids")
    ):
        raise ContractCleaningError("subagent packet identity differs from its frozen plan")


def _blind_proposal_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    payload = _proposal_payload(row)
    payload.pop("producer_source_assessment")
    return payload


def _repair_rows(value: Any, tasks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if (
        not isinstance(value, list)
        or len(value) != len(tasks)
        or any(not isinstance(row, dict) or set(row) != _REPAIR_FIELDS for row in value)
    ):
        raise ContractCleaningError("subagent repairs must be one exact JSON array")
    by_task = _unique_by(value, "task_unit_id", "subagent repair decisions")
    expected = {item["task_unit_id"] for item in tasks}
    if set(by_task) != expected:
        raise ContractCleaningError("subagent repair task identities differ")
    ordered = []
    for index, item in enumerate(tasks, start=1):
        row = by_task[item["task_unit_id"]]
        ordered.append(
            {
                "item_index": index,
                **{key: value for key, value in row.items() if key != "task_unit_id"},
            }
        )
    raw = json.dumps({"items": ordered}, ensure_ascii=False).encode()
    return _parse_contract_repairs(raw, tasks)


def _review_tuple(review: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        review["contract_status"],
        review["evidence_status"],
        review["source_specification_disposition"],
    )


def _validate_review_record_identity(review: Mapping[str, Any]) -> None:
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
    ):
        raise ContractCleaningError("contract review record identity is invalid")


__all__ = [
    "finalize_subagent_contract_repairs",
    "finalize_subagent_contract_reviews",
    "merge_subagent_contract_reviews",
    "prepare_subagent_contract_repairs",
    "prepare_subagent_contract_reviews",
    "seal_initial_subagent_contract_reviews",
]

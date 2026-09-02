"""Blind independent-agent review closure for prospective source-only gold."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from prompt_mechanism_study.artifact_io import (
    bundle_digest,
    file_sha256,
    read_json_exact,
    verify_bundle,
    write_bundle,
)


_PROTOCOL_ID = "isolated_dual_source_gold_review_with_blind_third_decision_v1"
_CONTRACT_PROTOCOL_ID = "task_context_contract_v2_dual_blind_consensus"
_EXTRACTOR_CANDIDATE_ID = (
    "dual-blind-consensus:prompt-contract-proposer-qwen37flash-v1+"
    "prompt-contract-reviewer-qwen37flash-v1"
)
_CONTEXT_STATES = {"present", "absent", "unresolved", "absent_or_unresolved"}
_ATTESTATION = {
    "forked_without_prior_turns": True,
    "only_exact_review_packets_read": True,
    "prohibited_inputs_read": False,
    "arms_or_outcomes_used": False,
}


def prepare_source_gold_adjudication(
    candidate_bundle: Path,
    reviewer_a_path: Path,
    reviewer_b_path: Path,
    output: Path,
) -> dict[str, Any]:
    """Validate two blind reviews and emit source-only third-review cases."""

    packets = _load_packets(candidate_bundle)
    reviewer_a = _load_decisions(reviewer_a_path, "reviewer-a", packets)
    reviewer_b = _load_decisions(reviewer_b_path, "reviewer-b", packets)
    disagreements = []
    counts: Counter[str] = Counter()
    for role, task_id in _ordered_case_keys(packets):
        a = reviewer_a[(role, task_id)]
        b = reviewer_b[(role, task_id)]
        if _decision_coordinate(a) == _decision_coordinate(b):
            counts[f"{role}:agreement"] += 1
            continue
        counts[f"{role}:disagreement"] += 1
        source_case = packets[role]["case_by_id"][task_id]
        disagreements.append({"proposed_data_role": role, **source_case})

    packet = {
        "schema_version": "1.0",
        "artifact_kind": "blind_source_gold_third_review_packet",
        "protocol_id": _PROTOCOL_ID,
        "status": (
            "AWAITING_BLIND_THIRD_REVIEW" if disagreements else "NO_DISAGREEMENTS"
        ),
        "reviewer_slot": "reviewer-c",
        "allowed_inputs": [
            "the exact source-only cases in this packet",
            "the finite catalog semantics, relations, guidance, and realizations in each case",
        ],
        "prohibited_inputs": packets["QUAL_DEV"]["packet"]["prohibited_inputs"]
        + ["reviewer-a decisions", "reviewer-b decisions"],
        "annotation_fields": packets["QUAL_DEV"]["packet"]["annotation_fields"],
        "prior_review_decisions_included": False,
        "cases": disagreements,
        "arms_or_outcomes_used": False,
    }
    report = {
        "schema_version": "1.0",
        "status": packet["status"],
        "protocol_id": _PROTOCOL_ID,
        "candidate_bundle_manifest_sha256": file_sha256(
            candidate_bundle.resolve() / "manifest.json"
        ),
        "review_packet_sha256s": {
            role: file_sha256(details["packet_path"])
            for role, details in packets.items()
        },
        "review_decision_sha256s": {
            "reviewer-a": file_sha256(reviewer_a_path),
            "reviewer-b": file_sha256(reviewer_b_path),
        },
        "agreements": sum(value for key, value in counts.items() if key.endswith(":agreement")),
        "disagreements": len(disagreements),
        "by_role": {
            role: {
                "agreements": counts[f"{role}:agreement"],
                "disagreements": counts[f"{role}:disagreement"],
            }
            for role in ("QUAL_DEV", "QUAL_ACCEPT")
        },
        "blind_third_review_required": bool(disagreements),
        "provider_calls": 0,
        "arms_or_outcomes_used": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(output, {"adjudication-review-packet.json": packet, "report.json": report})
    return {**report, "bundle_sha256": bundle_digest(output)}


def finalize_source_gold_review(
    repository_root: Path,
    candidate_bundle: Path,
    reviewer_a_path: Path,
    reviewer_b_path: Path,
    adjudication_bundle: Path,
    adjudicator_path: Path | None,
    output: Path,
) -> dict[str, Any]:
    """Freeze qualification-ready gold without making a formal role assignment."""

    root = repository_root.resolve()
    destination = output.resolve()
    try:
        destination.relative_to(root)
    except ValueError:
        raise ValueError("source gold output must remain beneath the repository root") from None
    packets = _load_packets(candidate_bundle)
    reviewer_a = _load_decisions(reviewer_a_path, "reviewer-a", packets)
    reviewer_b = _load_decisions(reviewer_b_path, "reviewer-b", packets)
    verify_bundle(adjudication_bundle)
    adjudication_packet = read_json_exact(
        adjudication_bundle.resolve() / "adjudication-review-packet.json"
    )
    expected_disagreements = {
        (role, task_id)
        for role, task_id in _ordered_case_keys(packets)
        if _decision_coordinate(reviewer_a[(role, task_id)])
        != _decision_coordinate(reviewer_b[(role, task_id)])
    }
    packet_keys = {
        (case.get("proposed_data_role"), case.get("task_id"))
        for case in adjudication_packet.get("cases", [])
        if isinstance(case, dict)
    }
    if (
        adjudication_packet.get("protocol_id") != _PROTOCOL_ID
        or adjudication_packet.get("prior_review_decisions_included") is not False
        or packet_keys != expected_disagreements
    ):
        raise ValueError("blind adjudication packet does not match reviewer disagreements")

    if expected_disagreements:
        if adjudicator_path is None:
            raise ValueError("blind third-review decisions are required")
        adjudicator = _load_decisions(
            adjudicator_path,
            "reviewer-c",
            packets,
            expected_keys=expected_disagreements,
        )
    else:
        if adjudicator_path is not None:
            raise ValueError("adjudicator decisions are invalid when no disagreements exist")
        adjudicator = {}

    final_cases: dict[str, list[dict[str, Any]]] = {"QUAL_DEV": [], "QUAL_ACCEPT": []}
    agreements = 0
    for role, task_id in _ordered_case_keys(packets):
        key = (role, task_id)
        if key in expected_disagreements:
            decision = adjudicator[key]
        else:
            decision = reviewer_a[key]
            agreements += 1
        final_cases[role].append(
            {
                "task_id": task_id,
                "expected_context": decision["expected_context"],
                "expected_realization_id": decision["expected_realization_id"],
                "rationale": decision["rationale"],
            }
        )

    artifacts: dict[str, Any] = {}
    selection_paths: dict[str, str] = {}
    for role, prefix in (("QUAL_DEV", "qual-dev"), ("QUAL_ACCEPT", "qual-accept")):
        details = packets[role]
        tasks_path = details["tasks_path"]
        selection_name = f"{prefix}-selection.json"
        selection_paths[role] = (destination / selection_name).relative_to(root).as_posix()
        artifacts[selection_name] = {
            "schema_version": "1.0",
            "source_tasks_sha256": file_sha256(tasks_path),
            "selection_rule": (
                "Use the exact prospectively reserved, source-only reviewed candidate order; "
                "the reservation is not a formal five-role assignment."
            ),
            "task_ids": details["task_ids"],
            "arms_or_outcomes_used": False,
        }
        artifacts[f"{prefix}-gold.json"] = {
            "schema_version": "2.0",
            "contract_protocol_id": _CONTRACT_PROTOCOL_ID,
            "extractor_candidate_id": _EXTRACTOR_CANDIDATE_ID,
            "selection_path": selection_paths[role],
            "review_completed_before_extraction": True,
            "arms_or_outcomes_used": False,
            "execution": {"task_workers": 4},
            "qualification_rule": details["template"]["qualification_rule"],
            "cases": final_cases[role],
        }

    decision_hashes = {
        "reviewer-a": file_sha256(reviewer_a_path),
        "reviewer-b": file_sha256(reviewer_b_path),
    }
    if adjudicator_path is not None:
        decision_hashes["reviewer-c"] = file_sha256(adjudicator_path)
    artifacts["reviewer-a-decisions.json"] = read_json_exact(reviewer_a_path)
    artifacts["reviewer-b-decisions.json"] = read_json_exact(reviewer_b_path)
    artifacts["adjudication-review-packet.json"] = adjudication_packet
    if adjudicator_path is not None:
        artifacts["reviewer-c-decisions.json"] = read_json_exact(adjudicator_path)
    receipt = {
        "schema_version": "1.0",
        "artifact_kind": "independent_subagent_source_gold_execution_receipt",
        "protocol_id": _PROTOCOL_ID,
        "reviewer_backend": "codex_collaboration_subagent_inherited_model_unseeded",
        "human_external_review": False,
        "reviewer_slots": ["reviewer-a", "reviewer-b", "reviewer-c"],
        "reviewer_a_and_b_reviewed_all_cases_independently": True,
        "third_reviewer_saw_only_source_cases_for_disagreements": True,
        "root_agent_made_semantic_decisions": False,
        "independence_attestation": _ATTESTATION,
        "candidate_bundle_manifest_sha256": file_sha256(
            candidate_bundle.resolve() / "manifest.json"
        ),
        "adjudication_bundle_manifest_sha256": file_sha256(
            adjudication_bundle.resolve() / "manifest.json"
        ),
        "decision_sha256s": decision_hashes,
        "agreement_count": agreements,
        "blind_third_review_count": len(expected_disagreements),
        "review_completed_before_extraction": True,
        "arms_or_outcomes_used": False,
    }
    report = {
        "schema_version": "1.0",
        "status": "INDEPENDENT_SUBAGENT_SOURCE_GOLD_COMPLETE_NOT_FORMAL_ROLE_ASSIGNMENT",
        "protocol_id": "phase-context-policy-v3",
        "source_gold_protocol_id": _PROTOCOL_ID,
        "task_units": {role: len(cases) for role, cases in final_cases.items()},
        "agreement_count": agreements,
        "blind_third_review_count": len(expected_disagreements),
        "independent_gold_complete": True,
        "human_external_review_complete": False,
        "formal_role_assignment_frozen": False,
        "qualification_accept_attempts_authorized": 0,
        "provider_calls_authorized": 0,
        "arms_or_outcomes_used": False,
        "scientific_claim_allowed": False,
        "next_gate": (
            "Run QUAL_DEV only; freeze the integrated qualification plan and a complete "
            "power-qualified five-role manifest before the one-shot QUAL_ACCEPT call."
        ),
    }
    artifacts["review-execution-receipt.json"] = receipt
    artifacts["report.json"] = report
    write_bundle(destination, artifacts)
    return {**report, "bundle_sha256": bundle_digest(destination)}


def _load_packets(candidate_bundle: Path) -> dict[str, dict[str, Any]]:
    root = candidate_bundle.resolve()
    verify_bundle(root)
    packets: dict[str, dict[str, Any]] = {}
    for role, prefix in (("QUAL_DEV", "qual-dev"), ("QUAL_ACCEPT", "qual-accept")):
        packet_path = root / f"{prefix}-review-packet.json"
        tasks_path = root / f"{prefix}-tasks.json"
        template_path = root / f"{prefix}-gold-template.json"
        packet = read_json_exact(packet_path)
        tasks = read_json_exact(tasks_path)
        template = read_json_exact(template_path)
        if (
            not isinstance(packet, dict)
            or packet.get("proposed_data_role") != role
            or packet.get("arms_or_outcomes_used") is not False
            or packet.get("reviewer_independence_required") is not True
            or not isinstance(packet.get("cases"), list)
            or not isinstance(tasks, list)
            or not isinstance(template, dict)
            or template.get("candidate_data_id") != packet.get("candidate_data_id")
            or template.get("arms_or_outcomes_used") is not False
        ):
            raise ValueError("source-only qualification review packet is invalid")
        case_by_id = {case.get("task_id"): case for case in packet["cases"]}
        task_ids = [task.get("task_id") for task in tasks]
        if None in case_by_id or len(case_by_id) != len(packet["cases"]) or task_ids != list(case_by_id):
            raise ValueError("source-only review packet task order differs")
        packets[role] = {
            "packet": packet,
            "packet_path": packet_path,
            "tasks_path": tasks_path,
            "template": template,
            "case_by_id": case_by_id,
            "task_ids": task_ids,
        }
    return packets


def _load_decisions(
    path: Path,
    expected_slot: str,
    packets: Mapping[str, Mapping[str, Any]],
    *,
    expected_keys: set[tuple[str, str]] | None = None,
) -> dict[tuple[str, str], dict[str, Any]]:
    value = read_json_exact(path)
    if (
        not isinstance(value, dict)
        or set(value)
        != {"schema_version", "protocol_id", "reviewer_slot", "independence_attestation", "cases"}
        or value["schema_version"] != "1.0"
        or value["protocol_id"] != _PROTOCOL_ID
        or value["reviewer_slot"] != expected_slot
        or value["independence_attestation"] != _ATTESTATION
        or not isinstance(value["cases"], list)
    ):
        raise ValueError(f"{expected_slot} source-gold decisions are invalid")
    decisions: dict[tuple[str, str], dict[str, Any]] = {}
    for decision in value["cases"]:
        if not isinstance(decision, dict) or set(decision) != {
            "proposed_data_role",
            "task_id",
            "expected_context",
            "expected_realization_id",
            "rationale",
        }:
            raise ValueError(f"{expected_slot} source-gold case is invalid")
        role = decision["proposed_data_role"]
        task_id = decision["task_id"]
        if role not in packets or task_id not in packets[role]["case_by_id"]:
            raise ValueError(f"{expected_slot} source-gold case is outside the packets")
        context = decision["expected_context"]
        realization = decision["expected_realization_id"]
        candidates = {
            row["realization_id"]
            for row in packets[role]["case_by_id"][task_id]["candidate_realizations"]
        }
        if (
            context not in _CONTEXT_STATES
            or (context == "present" and realization not in candidates)
            or (context != "present" and realization is not None)
            or not isinstance(decision["rationale"], str)
            or not decision["rationale"].strip()
        ):
            raise ValueError(f"{expected_slot} source-gold decision value is invalid")
        key = (role, task_id)
        if key in decisions:
            raise ValueError(f"{expected_slot} duplicates a source-gold case")
        decisions[key] = decision
    expected = expected_keys if expected_keys is not None else set(_ordered_case_keys(packets))
    if set(decisions) != expected:
        raise ValueError(f"{expected_slot} source-gold population is incomplete")
    return decisions


def _ordered_case_keys(
    packets: Mapping[str, Mapping[str, Any]],
) -> list[tuple[str, str]]:
    return [
        (role, task_id)
        for role in ("QUAL_DEV", "QUAL_ACCEPT")
        for task_id in packets[role]["task_ids"]
    ]


def _decision_coordinate(decision: Mapping[str, Any]) -> tuple[Any, Any]:
    return decision["expected_context"], decision["expected_realization_id"]


__all__ = ["finalize_source_gold_review", "prepare_source_gold_adjudication"]

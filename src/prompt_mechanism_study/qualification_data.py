"""Outcome-blind preparation of source-only qualification review packets."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from prompt_mechanism_study.artifact_io import (
    bundle_digest,
    file_sha256,
    write_bundle,
)
from prompt_mechanism_study.contract_cleaning import verify_contract_content_data
from prompt_mechanism_study.mechanisms import load_mechanism_registry
from prompt_mechanism_study.prompt_contract_extract import contract_decision_request
from prompt_mechanism_study.prompt_tsg import load_catalog
from prompt_mechanism_study.records import canonical_json, content_hash, content_id, require_text


_QUALIFICATION_RULE = {
    "minimum_exact_context_accuracy": 0.9,
    "minimum_present_recall": 0.8,
    "maximum_false_positive_present": 0,
    "maximum_wrong_realization": 0,
}
_FORBIDDEN_REVIEW_INPUTS = [
    "preexisting mechanism binding or readiness label",
    "proposer or reviewer response",
    "Prompt TSG or extractor output",
    "generated code",
    "arm or assignment",
    "Security Oracle or Functional Judge result",
    "discovery, confirmation, or experimental outcome",
]


def prepare_qualification_source_review(
    source_bundle: Path,
    catalog_path: Path,
    registry_path: Path,
    output: Path,
    *,
    producer_commit: str,
    ranking_salt: str,
    qual_dev_count: int = 28,
    qual_accept_count: int = 28,
) -> dict[str, Any]:
    """Prepare disjoint candidate reservations and blind review packets.

    This does not assign a formal data role. It freezes exact candidate
    memberships so an independent reviewer can create source-only gold before
    the one-shot acceptance set is ever sent to the candidate extractor.
    """

    require_text(ranking_salt, "ranking_salt")
    if (
        not isinstance(producer_commit, str)
        or len(producer_commit) != 40
        or any(character not in "0123456789abcdef" for character in producer_commit)
    ):
        raise ValueError("producer_commit must be a full lowercase Git commit")
    if (
        type(qual_dev_count) is not int
        or type(qual_accept_count) is not int
        or qual_dev_count < 1
        or qual_accept_count < 1
    ):
        raise ValueError("qualification candidate counts must be positive integers")

    source = source_bundle.resolve()
    verified = verify_contract_content_data(source)
    catalog = load_catalog(catalog_path)
    registry = load_mechanism_registry(registry_path)
    catalog_sha256 = file_sha256(catalog_path)
    registry_sha256 = file_sha256(registry_path)
    source_manifest_sha256 = file_sha256(source / "manifest.json")

    tasks = _rows_by_id(source / "task-units.jsonl", "task_unit_id")
    quality = _rows_by_id(source / "task-quality.jsonl", "task_unit_id")
    roles = _rows_by_id(source / "task-roles.jsonl", "task_unit_id")
    readiness = _rows_by_id(source / "readiness-worklist.jsonl", "task_unit_id")
    if any(set(rows) != set(tasks) for rows in (quality, roles, readiness)):
        raise ValueError("qualification source populations differ")

    query_by_realization: dict[str, dict[str, str]] = {}
    families_by_cwe: dict[str, set[str]] = defaultdict(set)
    queries_by_scope: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for query in catalog["queries"]:
        realization_id = query["realization_id"]
        coordinate = {
            "cwe": query["cwe_id"],
            "task_family": query["task_family"],
        }
        previous = query_by_realization.setdefault(realization_id, coordinate)
        if previous != coordinate or realization_id not in registry:
            raise ValueError("catalog and mechanism registry realization coordinates differ")
        families_by_cwe[query["cwe_id"]].add(query["task_family"])
        queries_by_scope[(query["cwe_id"], query["task_family"])].append(query)

    eligible = []
    for task_id, task in tasks.items():
        quality_row = quality[task_id]
        role = roles[task_id]
        ready = readiness[task_id]
        if (
            task["pre_treatment_source_metadata"]["language"] != "python"
            or quality_row["quality_disposition"] != "QUALITY_INCLUDED"
            or role["data_role"] != "UNASSIGNED"
            or role["exposure_status"] != "SOURCE_CURATED_ONLY"
            or role["exposure_data_ids"] != []
            or role["exposure_evidence"] != []
            or role["prospective_formal_role_assigned"] is not False
            or role["role_assignment_status"] != "PENDING_PROSPECTIVE_ALLOCATION"
            or not isinstance(role["future_evaluation_reservation_id"], str)
        ):
            continue
        cwes = task["pre_treatment_source_metadata"]["source_declared_cwe_ids"]
        if not isinstance(cwes, list) or len(cwes) != 1:
            continue
        cwe = cwes[0]
        realization_id = ready["mechanism_realization_id"]
        if realization_id is not None:
            coordinate = query_by_realization.get(realization_id)
            if coordinate is None or coordinate["cwe"] != cwe:
                continue
            task_family = coordinate["task_family"]
        else:
            families = families_by_cwe.get(cwe, set())
            if len(families) != 1:
                continue
            task_family = next(iter(families))
        eligible.append(
            {
                "task_id": task_id,
                "task": task,
                "role": role,
                "cwe": cwe,
                "task_family": task_family,
                "realization_id": realization_id,
            }
        )

    by_realization: dict[str, list[dict[str, Any]]] = defaultdict(list)
    unbound = []
    for row in eligible:
        if row["realization_id"] is None:
            unbound.append(row)
        else:
            by_realization[row["realization_id"]].append(row)
    if len(by_realization) > qual_accept_count:
        raise ValueError("QUAL_ACCEPT candidate count cannot cover every bound realization stratum")

    used_groups: set[str] = set()
    selected: dict[str, list[dict[str, Any]]] = {
        "QUAL_ACCEPT": [],
        "QUAL_DEV": [],
    }
    counts = {
        role: {"cwe": Counter(), "lineage": Counter()}
        for role in selected
    }

    for realization_id in sorted(by_realization):
        _select_one(
            by_realization[realization_id],
            selected["QUAL_ACCEPT"],
            used_groups,
            counts["QUAL_ACCEPT"],
            ranking_salt,
            "QUAL_ACCEPT",
            realization_id,
        )
    for realization_id in sorted(by_realization):
        remaining = [
            row
            for row in by_realization[realization_id]
            if row["role"]["near_duplicate_group_id"] not in used_groups
        ]
        if remaining:
            _select_one(
                remaining,
                selected["QUAL_DEV"],
                used_groups,
                counts["QUAL_DEV"],
                ranking_salt,
                "QUAL_DEV",
                realization_id,
            )

    _fill_selection(
        unbound,
        selected["QUAL_ACCEPT"],
        qual_accept_count,
        used_groups,
        counts["QUAL_ACCEPT"],
        ranking_salt,
        "QUAL_ACCEPT",
    )
    _fill_selection(
        unbound,
        selected["QUAL_DEV"],
        qual_dev_count,
        used_groups,
        counts["QUAL_DEV"],
        ranking_salt,
        "QUAL_DEV",
    )
    if (
        len(selected["QUAL_ACCEPT"]) != qual_accept_count
        or len(selected["QUAL_DEV"]) != qual_dev_count
    ):
        raise ValueError("qualification source population cannot fill both candidate reservations")

    artifacts: dict[str, Any] = {}
    summaries: dict[str, Any] = {}
    all_task_ids: set[str] = set()
    all_group_ids: set[str] = set()
    for role_name, prefix in (("QUAL_DEV", "qual-dev"), ("QUAL_ACCEPT", "qual-accept")):
        rows = selected[role_name]
        task_rows = [_extractor_task(row) for row in rows]
        task_payload_sha256 = _artifact_sha256(task_rows)
        membership = sorted(
            (
                {
                    "task_unit_id": row["task_id"],
                    "near_duplicate_group_id": row["role"]["near_duplicate_group_id"],
                    "source_lineage_id": row["role"]["source_lineage_id"],
                    "exposure_history": [],
                    "future_evaluation_reservation_id": row["role"][
                        "future_evaluation_reservation_id"
                    ],
                }
                for row in rows
            ),
            key=lambda item: item["task_unit_id"],
        )
        data_id = content_id(
            "qualification_dataset_candidate_",
            {
                "protocol_id": "phase-context-policy-v3",
                "proposed_role": role_name,
                "source_manifest_sha256": source_manifest_sha256,
                "task_manifest_sha256": task_payload_sha256,
                "task_units": membership,
            },
        )
        selection_record = {
            "schema_version": "1.0",
            "artifact_kind": "qualification_role_candidate_selection",
            "status": "CANDIDATE_RESERVATION_FROZEN_NOT_FORMAL_DATA_ROLE_MANIFEST",
            "protocol_id": "phase-context-policy-v3",
            "producer_commit": producer_commit,
            "data_id": data_id,
            "proposed_data_role": role_name,
            "formal_role_assigned": False,
            "qualification_accept_authorized": False,
            "source_manifest_sha256": source_manifest_sha256,
            "catalog_sha256": catalog_sha256,
            "registry_sha256": registry_sha256,
            "ranking_salt": ranking_salt,
            "selection_rule": (
                "one unexposed source-only candidate per existing catalog-bound realization "
                "for QUAL_ACCEPT; a second candidate where available for QUAL_DEV; fill each "
                "fixed count from unbound tasks whose CWE has one unambiguous catalog family, "
                "greedily balancing CWE and source lineage with salted SHA-256 tie-breaks"
            ),
            "existing_binding_metadata_used_only_for_stratified_selection": True,
            "task_manifest_sha256": task_payload_sha256,
            "task_ids_in_review_order": [row["task_id"] for row in rows],
            "task_units": membership,
            "arms_or_outcomes_used": False,
            "scientific_claim_allowed": False,
        }
        review_cases = []
        for task_row in task_rows:
            request = contract_decision_request(task_row, catalog)
            scope_queries = queries_by_scope[(task_row["cwe"], task_row["task_family"])]
            review_cases.append(
                {
                    "task_id": task_row["task_id"],
                    "source_reference": task_row["source"],
                    "annotation_request": request,
                    "candidate_realizations": [
                        {
                            "query_id": query["query_id"],
                            "realization_id": query["realization_id"],
                        }
                        for query in sorted(scope_queries, key=lambda item: item["query_id"])
                    ],
                }
            )
        review_packet = {
            "schema_version": "1.0",
            "artifact_kind": "source_only_prompt_contract_gold_review_packet",
            "status": "AWAITING_EXTERNAL_INDEPENDENT_REVIEW",
            "candidate_data_id": data_id,
            "proposed_data_role": role_name,
            "reviewer_independence_required": True,
            "allowed_inputs": [
                "exact natural source prompt in this packet",
                "source reference in this packet",
                "finite catalog queries, semantics, relations, and guidance in this packet",
            ],
            "prohibited_inputs": _FORBIDDEN_REVIEW_INPUTS,
            "annotation_fields": {
                "expected_context": [
                    "present",
                    "absent",
                    "unresolved",
                    "absent_or_unresolved",
                ],
                "expected_realization_id": (
                    "one candidate realization ID when expected_context is present; otherwise null"
                ),
                "rationale": "non-empty source-grounded explanation",
            },
            "cases": review_cases,
            "arms_or_outcomes_used": False,
        }
        gold_template = {
            "schema_version": "2.0-template",
            "status": "INCOMPLETE_EXTERNAL_INDEPENDENT_REVIEW_REQUIRED",
            "candidate_data_id": data_id,
            "contract_protocol_id": "task_context_contract_v2_dual_blind_consensus",
            "review_completed_before_extraction": False,
            "reviewer_independence_attested": False,
            "arms_or_outcomes_used": False,
            "execution": {"task_workers": 4},
            "qualification_rule": _QUALIFICATION_RULE,
            "cases": [
                {
                    "task_id": task["task_id"],
                    "expected_context": "REVIEW_REQUIRED",
                    "expected_realization_id": "REVIEW_REQUIRED_OR_NULL",
                    "rationale": "REVIEW_REQUIRED",
                }
                for task in task_rows
            ],
        }
        artifacts[f"{prefix}-selection.json"] = selection_record
        artifacts[f"{prefix}-tasks.json"] = task_rows
        artifacts[f"{prefix}-review-packet.json"] = review_packet
        artifacts[f"{prefix}-gold-template.json"] = gold_template
        task_ids = {row["task_id"] for row in rows}
        group_ids = {row["role"]["near_duplicate_group_id"] for row in rows}
        if all_task_ids.intersection(task_ids) or all_group_ids.intersection(group_ids):
            raise ValueError(
                "qualification candidate reservations cross task or near-duplicate roles"
            )
        all_task_ids.update(task_ids)
        all_group_ids.update(group_ids)
        summaries[role_name] = {
            "data_id": data_id,
            "task_units": len(rows),
            "bound_realization_strata": len(
                {row["realization_id"] for row in rows if row["realization_id"] is not None}
            ),
            "unbound_catalog_cwe_challenges": sum(
                row["realization_id"] is None for row in rows
            ),
            "source_lineages": dict(
                sorted(
                    Counter(
                        row["role"]["source_lineage_id"] for row in rows
                    ).items()
                )
            ),
            "cwes": dict(sorted(Counter(row["cwe"] for row in rows).items())),
            "task_manifest_sha256": task_payload_sha256,
        }

    report = {
        "schema_version": "1.0",
        "status": "SOURCE_ONLY_REVIEW_PACKETS_READY_FORMAL_ROLE_MANIFEST_AND_GOLD_PENDING",
        "protocol_id": "phase-context-policy-v3",
        "producer_commit": producer_commit,
        "source_bundle_sha256": verified["bundle_sha256"],
        "source_manifest_sha256": source_manifest_sha256,
        "catalog_sha256": catalog_sha256,
        "registry_sha256": registry_sha256,
        "eligible_unexposed_python_task_units": len(eligible),
        "candidate_reservations": summaries,
        "task_unit_disjoint": True,
        "near_duplicate_group_disjoint": True,
        "qual_accept_method_exposure_history_empty": True,
        "formal_role_assignment_frozen": False,
        "qualification_accept_attempts_authorized": 0,
        "provider_calls_authorized": 0,
        "independent_gold_complete": False,
        "next_gate": (
            "Obtain independent source-only labels without opening extractor outputs; approve "
            "and power-qualify all role counts; then freeze one complete five-role "
            "DataRoleManifest and "
            "the integrated acceptance plan before any QUAL_ACCEPT provider call."
        ),
        "arms_or_outcomes_used": False,
        "scientific_claim_allowed": False,
    }
    artifacts["report.json"] = report
    write_bundle(output, artifacts)
    return {**report, "bundle_sha256": bundle_digest(output)}


def _rows_by_id(path: Path, key: str) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        value = json.loads(line)
        if not isinstance(value, dict) or not isinstance(value.get(key), str):
            raise ValueError(f"invalid qualification source row: {path.name}")
        identity = value[key]
        if identity in rows:
            raise ValueError(f"duplicate qualification source identity: {identity}")
        rows[identity] = value
    return rows


def _rank(salt: str, role: str, stratum: str, task_id: str) -> str:
    return hashlib.sha256(f"{salt}\0{role}\0{stratum}\0{task_id}".encode("utf-8")).hexdigest()


def _select_one(
    candidates: Iterable[dict[str, Any]],
    destination: list[dict[str, Any]],
    used_groups: set[str],
    counts: Mapping[str, Counter[str]],
    salt: str,
    role: str,
    stratum: str,
) -> None:
    available = [
        row
        for row in candidates
        if row["role"]["near_duplicate_group_id"] not in used_groups
    ]
    if not available:
        raise ValueError(f"qualification stratum is unavailable: {role}/{stratum}")
    chosen = min(
        available,
        key=lambda row: (
            counts["lineage"][row["role"]["source_lineage_id"]],
            _rank(salt, role, stratum, row["task_id"]),
            row["task_id"],
        ),
    )
    destination.append(chosen)
    used_groups.add(chosen["role"]["near_duplicate_group_id"])
    counts["cwe"][chosen["cwe"]] += 1
    counts["lineage"][chosen["role"]["source_lineage_id"]] += 1


def _fill_selection(
    candidates: Iterable[dict[str, Any]],
    destination: list[dict[str, Any]],
    target: int,
    used_groups: set[str],
    counts: Mapping[str, Counter[str]],
    salt: str,
    role: str,
) -> None:
    pool = list(candidates)
    while len(destination) < target:
        available = [
            row
            for row in pool
            if row["role"]["near_duplicate_group_id"] not in used_groups
        ]
        if not available:
            raise ValueError(f"insufficient unbound source-only candidates for {role}")
        chosen = min(
            available,
            key=lambda row: (
                counts["cwe"][row["cwe"]],
                counts["lineage"][row["role"]["source_lineage_id"]],
                _rank(salt, role, "unbound", row["task_id"]),
                row["task_id"],
            ),
        )
        destination.append(chosen)
        used_groups.add(chosen["role"]["near_duplicate_group_id"])
        counts["cwe"][chosen["cwe"]] += 1
        counts["lineage"][chosen["role"]["source_lineage_id"]] += 1


def _extractor_task(row: Mapping[str, Any]) -> dict[str, Any]:
    task = row["task"]
    model_input = task["model_visible_input"]
    prompt = model_input["natural_prompt"]
    if model_input["natural_prompt_content_sha256"] != content_hash(prompt):
        raise ValueError("qualification source prompt identity drifted")
    representative = task["representative_record_id"]
    source_members = [
        member for member in task["source_members"] if member["record_id"] == representative
    ]
    if len(source_members) != 1:
        raise ValueError("qualification source representative provenance is missing")
    member = source_members[0]
    return {
        "task_id": row["task_id"],
        "task_unit_id": row["task_id"],
        "prompt": prompt,
        "prompt_sha256": content_hash(prompt),
        "language": "python",
        "cwe": row["cwe"],
        "task_family": row["task_family"],
        "source": {
            "dataset": member["dataset_id"],
            "source_lineage_id": task["source_lineage_id"],
            "repository": member["citation_url"],
            "version": member["source_version"],
            "upstream_id": member["source_item_id"],
            "source_locator": member["source_locator"],
            "source_record_sha256": member["source_record_sha256"],
        },
    }


def _artifact_sha256(value: Any) -> str:
    payload = (canonical_json(value) + "\n").encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


__all__ = ["prepare_qualification_source_review"]

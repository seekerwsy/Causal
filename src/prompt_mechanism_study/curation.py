"""Outcome-blind semantic clustering and functional-contract curation."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from prompt_mechanism_study.artifact_io import (
    bundle_digest,
    read_json,
    verify_bundle,
    write_bundle,
)
from prompt_mechanism_study.functional_judge import bailian_complete
from prompt_mechanism_study.records import canonical_value, content_id

# The frozen provider twice returned only the first ten items from 24-item
# requests and later returned eight of ten on a mixed-language batch.  Five is
# the conservative closed-response unit used by both outcome-blind stages; a
# response still has to bind every supplied index or the batch is rejected.
SEMANTIC_MAX_ITEMS = 5
CONTRACT_MAX_ITEMS = 5
CONTRACT_REVIEW_MAX_ITEMS = 5
MAX_BATCH_CHARS = 40_000
_LABELS = {"same_cluster", "related_but_independent", "different_task", "uncertain"}
_RESOLUTION = {"resolved", "ambiguous", "unsupported"}
_CONTRACT_REVIEW_STATUS = {"faithful", "faulty", "uncertain"}
_FUNCTIONAL_EVALUABILITY = {"sufficient", "limited", "insufficient"}
_CONTRACT_ISSUES = {
    "none",
    "unsupported_requirement",
    "missing_explicit_requirement",
    "entrypoint_mismatch",
    "input_mismatch",
    "output_mismatch",
    "side_effect_mismatch",
    "dependency_mismatch",
    "security_requirement_injected",
    "prompt_not_software_task",
    "external_context_missing",
    "ambiguous_interface",
    "uncertain_semantics",
    "other",
}
_RESPONSE_FORMAT_MARKERS = (
    "only return the code",
    "only output the code",
    "output only the code",
    "return only the code",
    "without preamble or suffix",
    "without a preamble or suffix",
    "don't include any other information",
    "do not include any other information",
)
_CLUSTER_ASSEMBLY_RULE = "exact_prompt_and_frozen_lineage_only_v1"
Provider = Callable[[dict[str, Any], Mapping[str, Any], str], bytes]


class CurationError(RuntimeError):
    """A frozen-input, provider, or response-contract failure."""


def run_semantic_curation(
    repository_root: Path,
    prepared_root: Path,
    candidates_root: Path,
    output: Path,
    *,
    max_new_batches: int | None = None,
    workers: int = 1,
    reuse_root: Path | None = None,
    provider: Provider = bailian_complete,
) -> dict[str, Any]:
    """Adjudicate every lexical pair and freeze connected semantic clusters."""

    root = repository_root.resolve()
    prepared = prepared_root.resolve()
    candidates = candidates_root.resolve()
    verify_bundle(prepared)
    verify_bundle(candidates)
    records = _rows(read_json(prepared / "records.json"), "records")
    pairs = sorted(
        _rows(read_json(candidates / "dedup-candidates.json"), "dedup candidates"),
        key=lambda item: item["pair_id"],
    )
    evaluator, prompt, identities = _policy(root, "semantic-adjudication-v5.txt")
    identities["response_binding"] = "batch_item_index_v1"
    identities["duplicate_index_policy"] = "last_occurrence_wins_if_all_indices_covered"
    identities["duplicate_json_key_policy"] = "collapse_only_type_and_value_identical_v1"
    identities["diagnostic_fields"] = "nonbinding_bounded_text_v1"
    batches = _batches(pairs, "pair_id", SEMANTIC_MAX_ITEMS, _pair_chars)
    base_plan = {
        "schema_version": "1.0",
        "stage": "semantic_adjudication",
        "prepared_bundle_sha256": bundle_digest(prepared),
        "candidates_bundle_sha256": bundle_digest(candidates),
        "record_count": len(records),
        "candidate_pair_count": len(pairs),
        "batch_item_limit": SEMANTIC_MAX_ITEMS,
        "batch_character_limit": MAX_BATCH_CHARS,
        "batch_ids": [[item["pair_id"] for item in batch] for batch in batches],
        "policy": identities,
        "outcomes_or_arm_labels_used": False,
    }
    reuse = _reuse_metadata(reuse_root, base_plan) if reuse_root is not None else None
    plan = {**base_plan, **({"reuse_source": reuse} if reuse is not None else {})}
    run_root = _initialize(output.resolve(), plan)
    if reuse_root is not None:
        _import_reuse(reuse_root.resolve(), run_root, reuse)
    decisions, complete = _execute(
        run_root,
        batches,
        evaluator,
        prompt,
        _semantic_request,
        _parse_semantic,
        max_new_batches,
        workers,
        provider,
    )
    progress = _progress("SEMANTIC_ADJUDICATION", len(batches), decisions, complete)
    if not complete:
        return progress
    final = run_root / "final"
    if final.exists():
        verify_bundle(final)
        return read_json(final / "report.json")
    return _freeze_clusters(prepared, candidates, records, decisions, final, plan)


def run_contract_curation(
    repository_root: Path,
    prepared_root: Path,
    clusters_root: Path,
    output: Path,
    *,
    max_new_batches: int | None = None,
    workers: int = 1,
    reuse_root: Path | None = None,
    existing_contracts_root: Path | None = None,
    provider: Provider = bailian_complete,
) -> dict[str, Any]:
    """Reuse matching contracts and extract only missing cluster contracts."""

    root = repository_root.resolve()
    prepared = prepared_root.resolve()
    clusters = clusters_root.resolve()
    verify_bundle(prepared)
    verify_bundle(clusters)
    records = {
        item["record_id"]: item for item in _rows(read_json(prepared / "records.json"), "records")
    }
    cluster_rows = _rows(read_json(clusters / "semantic-clusters.json"), "clusters")
    items = []
    for cluster in sorted(cluster_rows, key=lambda item: item["cluster_id"]):
        record = records[cluster["representative_record_id"]]
        items.append(
            {
                "cluster_id": cluster["cluster_id"],
                "record_id": record["record_id"],
                "source_prompt_sha256": record["prompt_sha256"],
                "language": record["language"],
                "source_prompt": record["prompt"],
            }
        )
    seeded, seed_metadata = _load_existing_contracts(existing_contracts_root, items)
    missing_items = [item for item in items if item["record_id"] not in seeded]
    evaluator, prompt, identities = _policy(root, "contract-extraction-v7.txt")
    identities["response_binding"] = "batch_item_index_v1"
    identities["duplicate_index_policy"] = "last_occurrence_wins_if_all_indices_covered"
    identities["duplicate_json_key_policy"] = "collapse_only_type_and_value_identical_v1"
    batches = _batches(missing_items, "record_id", CONTRACT_MAX_ITEMS, _contract_chars)
    base_plan = {
        "schema_version": "1.0",
        "stage": "functional_contract_extraction",
        "prepared_bundle_sha256": bundle_digest(prepared),
        "semantic_clusters_bundle_sha256": bundle_digest(clusters),
        "cluster_count": len(cluster_rows),
        "reused_contract_count": len(seeded),
        "new_contract_count": len(missing_items),
        "existing_contracts": seed_metadata,
        "batch_item_limit": CONTRACT_MAX_ITEMS,
        "batch_character_limit": MAX_BATCH_CHARS,
        "batch_ids": [[item["record_id"] for item in batch] for batch in batches],
        "policy": identities,
        "outcomes_or_arm_labels_used": False,
    }
    reuse = _reuse_metadata(reuse_root, base_plan) if reuse_root is not None else None
    plan = {**base_plan, **({"reuse_source": reuse} if reuse is not None else {})}
    run_root = _initialize(output.resolve(), plan)
    if reuse_root is not None:
        _import_reuse(reuse_root.resolve(), run_root, reuse)
    contracts, complete = _execute(
        run_root,
        batches,
        evaluator,
        prompt,
        _contract_request,
        _parse_contracts,
        max_new_batches,
        workers,
        provider,
    )
    progress = {
        **_progress("FUNCTIONAL_CONTRACT_EXTRACTION", len(batches), contracts, complete),
        "reused_contract_count": len(seeded),
        "new_contract_count": len(missing_items),
        "total_cluster_count": len(items),
    }
    if not complete:
        return progress
    final = run_root / "final"
    if final.exists():
        verify_bundle(final)
        return read_json(final / "report.json")
    by_record = {**seeded, **{item["record_id"]: item for item in contracts}}
    if set(by_record) != {item["record_id"] for item in items}:
        raise CurationError("reused and extracted contracts do not cover every cluster")
    frozen = []
    for item in items:
        value = {**by_record[item["record_id"]], "cluster_id": item["cluster_id"]}
        value["contract_id"] = content_id("cluster_contract_", value)
        frozen.append(value)
    frozen.sort(key=lambda item: item["cluster_id"])
    statuses = Counter(item["resolution_status"] for item in frozen)
    report = {
        "schema_version": "1.0",
        "status": "FUNCTIONAL_CONTRACTS_FROZEN",
        "semantic_clusters_bundle_sha256": bundle_digest(clusters),
        "contract_count": len(frozen),
        "reused_contract_count": len(seeded),
        "newly_extracted_contract_count": len(contracts),
        "resolution_status_counts": dict(sorted(statuses.items())),
        "all_clusters_accounted_for": len(frozen) == len(cluster_rows),
        "outcomes_or_arm_labels_used": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(final, {"functional-contracts.json": frozen, "report.json": report})
    return report


def run_contract_quality_review(
    repository_root: Path,
    prepared_root: Path,
    contracts_root: Path,
    output: Path,
    *,
    max_new_batches: int | None = None,
    workers: int = 1,
    reuse_root: Path | None = None,
    provider: Provider = bailian_complete,
) -> dict[str, Any]:
    """Blindly triage every extracted contract before independent adjudication."""

    root = repository_root.resolve()
    prepared = prepared_root.resolve()
    contracts = contracts_root.resolve()
    verify_bundle(prepared)
    verify_bundle(contracts)
    records = {
        item["record_id"]: item for item in _rows(read_json(prepared / "records.json"), "records")
    }
    contract_rows = sorted(
        _rows(read_json(contracts / "functional-contracts.json"), "functional contracts"),
        key=lambda item: item["cluster_id"],
    )
    items: list[dict[str, Any]] = []
    seen_records: set[str] = set()
    seen_clusters: set[str] = set()
    for contract in contract_rows:
        record_id = contract.get("record_id")
        cluster_id = contract.get("cluster_id")
        record = records.get(record_id)
        contract_core = {key: value for key, value in contract.items() if key != "contract_id"}
        if (
            record is None
            or not isinstance(cluster_id, str)
            or record_id in seen_records
            or cluster_id in seen_clusters
            or contract.get("source_prompt_sha256") != record.get("prompt_sha256")
            or contract.get("contract_id") != content_id("cluster_contract_", contract_core)
        ):
            raise CurationError("contract review inputs are not one-to-one and prompt-bound")
        seen_records.add(record_id)
        seen_clusters.add(cluster_id)
        items.append(
            {
                "cluster_id": cluster_id,
                "contract_id": contract["contract_id"],
                "record_id": record_id,
                "language": record["language"],
                "source_prompt": record["prompt"],
                "deterministic_issue_codes": _deterministic_contract_issues(contract),
                "contract": {
                    key: contract[key]
                    for key in (
                        "entrypoint",
                        "requirements",
                        "inputs",
                        "outputs",
                        "side_effects",
                        "environment_dependencies",
                    )
                },
            }
        )
    evaluator, prompt, identities = _policy(
        root,
        "functional-contract-review-v1.txt",
        config_name="qwen37max-contract-review.json",
    )
    identities["response_binding"] = "batch_item_index_v1"
    identities["review_scope"] = "source_prompt_and_contract_only_v1"
    batches = _batches(
        items,
        "cluster_id",
        CONTRACT_REVIEW_MAX_ITEMS,
        _contract_review_chars,
    )
    base_plan = {
        "schema_version": "1.0",
        "stage": "functional_contract_quality_review",
        "prepared_bundle_sha256": bundle_digest(prepared),
        "contracts_bundle_sha256": bundle_digest(contracts),
        "contract_count": len(items),
        "batch_item_limit": CONTRACT_REVIEW_MAX_ITEMS,
        "batch_character_limit": MAX_BATCH_CHARS,
        "batch_ids": [[item["cluster_id"] for item in batch] for batch in batches],
        "policy": identities,
        "cwe_arm_or_outcomes_used": False,
        "reviewer_candidate_rule": (
            "no_deterministic_issue_and_faithful_and_functionally_sufficient_v1"
        ),
    }
    reuse = _reuse_metadata(reuse_root, base_plan) if reuse_root is not None else None
    plan = {**base_plan, **({"reuse_source": reuse} if reuse is not None else {})}
    run_root = _initialize(output.resolve(), plan)
    if reuse_root is not None:
        _import_reuse(reuse_root.resolve(), run_root, reuse)
    reviews, complete = _execute(
        run_root,
        batches,
        evaluator,
        prompt,
        _contract_review_request,
        _parse_contract_reviews,
        max_new_batches,
        workers,
        provider,
    )
    progress = _progress("FUNCTIONAL_CONTRACT_QUALITY_REVIEW", len(batches), reviews, complete)
    if not complete:
        return progress
    final = run_root / "final"
    if final.exists():
        verify_bundle(final)
        return read_json(final / "report.json")
    review_by_cluster = {item["cluster_id"]: item for item in reviews}
    if set(review_by_cluster) != {item["cluster_id"] for item in items}:
        raise CurationError("contract reviews do not cover every cluster")
    frozen_reviews = []
    reviewer_qualified_contracts = []
    contracts_by_cluster = {item["cluster_id"]: item for item in contract_rows}
    for item in items:
        review = review_by_cluster[item["cluster_id"]]
        reviewer_qualified = (
            not item["deterministic_issue_codes"]
            and review["contract_status"] == "faithful"
            and review["functional_evaluability"] == "sufficient"
        )
        frozen_reviews.append(
            {
                "cluster_id": item["cluster_id"],
                "contract_id": item["contract_id"],
                "record_id": item["record_id"],
                **{key: value for key, value in review.items() if key != "cluster_id"},
                "deterministic_issue_codes": item["deterministic_issue_codes"],
                "reviewer_qualified": reviewer_qualified,
            }
        )
        if reviewer_qualified:
            reviewer_qualified_contracts.append(contracts_by_cluster[item["cluster_id"]])
    status_counts = Counter(item["contract_status"] for item in frozen_reviews)
    evaluability_counts = Counter(item["functional_evaluability"] for item in frozen_reviews)
    issue_counts = Counter(
        issue for item in frozen_reviews for issue in item["issue_codes"] if issue != "none"
    )
    deterministic_issue_counts = Counter(
        issue for item in frozen_reviews for issue in item["deterministic_issue_codes"]
    )
    report = {
        "schema_version": "1.0",
        "status": "FUNCTIONAL_CONTRACT_REVIEW_TRIAGE_FROZEN",
        "contract_count": len(contract_rows),
        "review_count": len(frozen_reviews),
        "reviewer_qualified_count": len(reviewer_qualified_contracts),
        "contract_status_counts": dict(sorted(status_counts.items())),
        "functional_evaluability_counts": dict(sorted(evaluability_counts.items())),
        "issue_counts": dict(sorted(issue_counts.items())),
        "deterministic_issue_counts": dict(sorted(deterministic_issue_counts.items())),
        "all_contracts_accounted_for": len(frozen_reviews) == len(contract_rows),
        "cwe_arm_or_outcomes_used": False,
        "semantic_quality_established": False,
        "final_experiment_eligibility_established": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(
        final,
        {
            "contract-quality-reviews.json": frozen_reviews,
            "reviewer-qualified-contracts.json": reviewer_qualified_contracts,
            "report.json": report,
        },
    )
    return report


def repair_response_format_contract_leaks(
    contracts_root: Path,
    output: Path,
) -> dict[str, Any]:
    """Remove response-format instructions from a successor contract bundle."""

    contracts = contracts_root.resolve()
    verify_bundle(contracts)
    contract_rows = _rows(
        read_json(contracts / "functional-contracts.json"),
        "functional contracts",
    )
    corrected: list[dict[str, Any]] = []
    repaired_only: list[dict[str, Any]] = []
    repairs: list[dict[str, Any]] = []
    seen_clusters: set[str] = set()
    for contract in contract_rows:
        cluster_id = contract.get("cluster_id")
        if not isinstance(cluster_id, str) or cluster_id in seen_clusters:
            raise CurationError("functional contracts have invalid task-unit identities")
        seen_clusters.add(cluster_id)
        original_core = {key: value for key, value in contract.items() if key != "contract_id"}
        if contract.get("contract_id") != content_id("cluster_contract_", original_core):
            raise CurationError("functional contract content identity is invalid")
        requirements = contract.get("requirements")
        if not isinstance(requirements, list) or any(
            not isinstance(requirement, str) or not requirement.strip()
            for requirement in requirements
        ):
            raise CurationError("contract requirements are invalid")
        removed = [
            requirement
            for requirement in requirements
            if _is_response_format_requirement(requirement)
        ]
        retained = [requirement for requirement in requirements if requirement not in removed]
        if removed and not retained:
            raise CurationError("format-leak repair would erase every functional requirement")
        corrected_core = {**original_core, "requirements": retained}
        corrected_contract = {
            **corrected_core,
            "contract_id": content_id("cluster_contract_", corrected_core),
        }
        corrected.append(corrected_contract)
        if removed:
            repaired_only.append(corrected_contract)
            repairs.append(
                {
                    "cluster_id": cluster_id,
                    "record_id": contract["record_id"],
                    "old_contract_id": contract["contract_id"],
                    "new_contract_id": corrected_contract["contract_id"],
                    "removed_requirements": removed,
                    "repair_code": "remove_response_format_instruction_v1",
                }
            )
    corrected.sort(key=lambda item: item["cluster_id"])
    repaired_only.sort(key=lambda item: item["cluster_id"])
    repairs.sort(key=lambda item: item["cluster_id"])
    report = {
        "schema_version": "1.0",
        "status": "FUNCTIONAL_CONTRACT_FORMAT_REPAIRS_FROZEN",
        "source_contracts_bundle_sha256": bundle_digest(contracts),
        "contract_count": len(corrected),
        "repaired_contract_count": len(repairs),
        "unchanged_contract_count": len(corrected) - len(repairs),
        "repair_rule": "remove_response_format_instruction_v1",
        "arms_or_outcomes_used": False,
        "semantic_quality_established": False,
        "final_experiment_eligibility_established": False,
        "scientific_claim_allowed": False,
    }
    destination = output.resolve()
    write_bundle(
        destination,
        {
            "functional-contracts.json": corrected,
            "repaired-contracts.json": repaired_only,
            "repairs.json": repairs,
            "report.json": report,
        },
    )
    return report


def assemble_semantic_clusters(
    prepared_root: Path,
    candidates_root: Path,
    adjudication_root: Path,
    output: Path,
) -> dict[str, Any]:
    """Assemble conservative clusters; retain LLM decisions as diagnostics."""

    prepared = prepared_root.resolve()
    candidates = candidates_root.resolve()
    adjudication = adjudication_root.resolve()
    destination = output.resolve()
    if destination.exists():
        raise CurationError("semantic cluster output already exists")
    verify_bundle(prepared)
    verify_bundle(candidates)
    verify_bundle(adjudication / "plan")
    source_plan = _object(read_json(adjudication / "plan/plan.json"), "adjudication plan")
    if source_plan["prepared_bundle_sha256"] != bundle_digest(prepared):
        raise CurationError("prepared bundle does not match adjudication plan")
    if source_plan["candidates_bundle_sha256"] != bundle_digest(candidates):
        raise CurationError("candidate bundle does not match adjudication plan")
    expected_batches = len(source_plan["batch_ids"])
    batch_roots = sorted((adjudication / "batches").iterdir())
    if [item.name for item in batch_roots] != [
        f"batch-{index:04d}" for index in range(1, expected_batches + 1)
    ]:
        raise CurationError("adjudication batch set is incomplete")
    decisions = []
    for batch_root in batch_roots:
        verify_bundle(batch_root)
        result = _object(read_json(batch_root / "result.json"), "adjudication result")
        if result.get("status") != "COMPLETE":
            raise CurationError("adjudication contains a non-complete batch")
        decisions.extend(_rows(result.get("items"), "adjudication decisions"))
    records = _rows(read_json(prepared / "records.json"), "records")
    plan = {
        **source_plan,
        "cluster_assembly_rule": _CLUSTER_ASSEMBLY_RULE,
        "source_adjudication_plan_sha256": bundle_digest(adjudication / "plan"),
        "source_adjudication_batch_sha256s": [bundle_digest(item) for item in batch_roots],
    }
    return _freeze_clusters(prepared, candidates, records, decisions, destination, plan)


def _policy(
    root: Path,
    prompt_name: str,
    *,
    config_name: str = "qwen35flash.json",
) -> tuple[dict[str, Any], str, dict[str, Any]]:
    config_path = root / f"data/dataset-curation/{config_name}"
    prompt_path = root / f"data/dataset-curation/{prompt_name}"
    evaluator = _object(read_json(config_path), "curation evaluator")
    prompt = prompt_path.read_text(encoding="utf-8").strip()
    if not prompt:
        raise CurationError("curation prompt is empty")
    return (
        evaluator,
        prompt,
        {
            "model_id": evaluator["model_id"],
            "config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
            "prompt_sha256": hashlib.sha256(prompt_path.read_bytes()).hexdigest(),
            "curation_implementation_sha256": hashlib.sha256(
                (root / "src/prompt_mechanism_study/curation.py").read_bytes()
            ).hexdigest(),
            "provider_adapter_sha256": hashlib.sha256(
                (root / "src/prompt_mechanism_study/functional_judge.py").read_bytes()
            ).hexdigest(),
            "temperature": evaluator["temperature"],
            "top_p": evaluator["top_p"],
            "seed": evaluator["seed"],
            "max_attempts": 1,
        },
    )


def _initialize(output: Path, plan: dict[str, Any]) -> Path:
    if not output.exists():
        output.mkdir(parents=True)
        write_bundle(output / "plan", {"plan.json": plan})
        (output / "batches").mkdir()
        return output
    verify_bundle(output / "plan")
    if read_json(output / "plan/plan.json") != canonical_value(plan):
        raise CurationError("existing run plan does not match the requested inputs")
    if not (output / "batches").is_dir():
        raise CurationError("curation batch directory is missing")
    allowed = {"plan", "batches", "reuse", "final"}
    if {item.name for item in output.iterdir()} - allowed:
        raise CurationError("curation run contains unexpected paths")
    return output


def _reuse_metadata(source: Path, base_plan: dict[str, Any]) -> dict[str, Any]:
    source = source.resolve()
    verify_bundle(source / "plan")
    old_plan = _object(read_json(source / "plan/plan.json"), "reuse plan")
    if {key: value for key, value in old_plan.items() if key != "reuse_source"} != base_plan:
        raise CurationError("reuse source was created from a different core plan")
    batches = []
    for batch_root in sorted((source / "batches").iterdir()):
        verify_bundle(batch_root)
        result = _object(read_json(batch_root / "result.json"), "reuse batch result")
        if result.get("status") == "COMPLETE":
            batches.append(
                {"batch_name": batch_root.name, "bundle_sha256": bundle_digest(batch_root)}
            )
    return {
        "source_root": str(source),
        "source_plan_bundle_sha256": bundle_digest(source / "plan"),
        "completed_batches": batches,
    }


def _import_reuse(source: Path, target: Path, metadata: dict[str, Any] | None) -> None:
    if metadata is None:
        raise CurationError("reuse metadata is missing")
    reuse_bundle = target / "reuse"
    if reuse_bundle.exists():
        verify_bundle(reuse_bundle)
        if read_json(reuse_bundle / "report.json") != canonical_value(metadata):
            raise CurationError("reuse evidence does not match the frozen plan")
        return
    for item in metadata["completed_batches"]:
        source_batch = source / "batches" / item["batch_name"]
        if bundle_digest(source_batch) != item["bundle_sha256"]:
            raise CurationError("reuse source batch drifted")
        target_batch = target / "batches" / item["batch_name"]
        if target_batch.exists():
            if bundle_digest(target_batch) != item["bundle_sha256"]:
                raise CurationError("target contains a conflicting reused batch")
            continue
        artifacts = {
            name: read_json(source_batch / name)
            for name in ("request.json", "response.json", "result.json")
        }
        write_bundle(target_batch, artifacts)
        if bundle_digest(target_batch) != item["bundle_sha256"]:
            raise CurationError("reused batch bytes are not exact")
    write_bundle(reuse_bundle, {"report.json": metadata})


def _execute(
    run_root: Path,
    batches: Sequence[Sequence[dict[str, Any]]],
    evaluator: Mapping[str, Any],
    prompt: str,
    request_builder: Callable[[Sequence[dict[str, Any]]], dict[str, Any]],
    parser: Callable[[bytes, Sequence[dict[str, Any]]], list[dict[str, Any]]],
    max_new_batches: int | None,
    workers: int,
    provider: Provider,
) -> tuple[list[dict[str, Any]], bool]:
    if max_new_batches is not None and (type(max_new_batches) is not int or max_new_batches <= 0):
        raise ValueError("max_new_batches must be a positive integer")
    if type(workers) is not int or not 1 <= workers <= 6:
        raise ValueError("workers must be an integer between one and six")
    expected_names = {f"batch-{index:04d}" for index in range(1, len(batches) + 1)}
    actual_names = {item.name for item in (run_root / "batches").iterdir()}
    if not actual_names <= expected_names:
        raise CurationError("unexpected batch output exists")
    accumulated: list[dict[str, Any]] = []
    pending: list[tuple[int, Sequence[dict[str, Any]]]] = []
    for index, batch in enumerate(batches, start=1):
        batch_root = run_root / "batches" / f"batch-{index:04d}"
        if batch_root.exists():
            verify_bundle(batch_root)
            result = _object(read_json(batch_root / "result.json"), "batch result")
            if result.get("status") != "COMPLETE":
                raise CurationError(f"batch {index} is a closed error and cannot be retried")
            accumulated.extend(_rows(result.get("items"), "batch items"))
            continue
        if max_new_batches is not None and len(pending) >= max_new_batches:
            break
        pending.append((index, batch))

    def execute_one(index: int, batch: Sequence[dict[str, Any]]) -> dict[str, Any]:
        batch_root = run_root / "batches" / f"batch-{index:04d}"
        request = request_builder(batch)
        raw: bytes | None = None
        try:
            raw = provider(request, evaluator, prompt)
            values = parser(raw, batch)
            result = {"schema_version": "1.0", "status": "COMPLETE", "items": values}
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception as failure:  # noqa: BLE001 - close the failed provider attempt
            result = {
                "schema_version": "1.0",
                "status": "ERROR",
                "error_type": type(failure).__name__,
                "items": [],
            }
        write_bundle(
            batch_root,
            {
                "request.json": request,
                "response.json": {
                    "raw_text": raw.decode("utf-8", errors="replace") if raw is not None else None
                },
                "result.json": result,
            },
        )
        return result

    for offset in range(0, len(pending), workers):
        group = pending[offset : offset + workers]
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(execute_one, index, batch) for index, batch in group]
            results = [future.result() for future in futures]
        for (index, _), result in zip(group, results, strict=True):
            if result["status"] != "COMPLETE":
                raise CurationError(f"batch {index} failed and was closed without retry")
            accumulated.extend(result["items"])
    complete = len(accumulated) == sum(len(batch) for batch in batches)
    return accumulated, complete


def _semantic_request(batch: Sequence[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "request_kind": "blind_semantic_task_adjudication",
        "blindness": {"outcomes_withheld": True, "arms_withheld": True, "sources_withheld": True},
        "pairs": [
            {
                "item_index": index,
                "language": item["language"],
                "task_a": item["left_prompt"],
                "task_b": item["right_prompt"],
            }
            for index, item in enumerate(batch, start=1)
        ],
    }


def _parse_semantic(raw: bytes, batch: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    value = _json_object(raw)
    if set(value) != {"decisions"}:
        raise CurationError("semantic response keys are not exact")
    rows = _rows(value["decisions"], "semantic decisions")
    rows = _last_by_index(rows, len(batch), "semantic response")
    for row in rows:
        keys = set(row)
        if not {"item_index", "label"} <= keys or row["label"] not in _LABELS:
            raise CurationError("semantic decision is malformed")
        reason = row.get("reason", row.get("description", "No diagnostic reason supplied."))
        _bounded(reason, 4000, "semantic reason")
        row["reason"] = reason
        row.pop("description", None)
    return [
        {"pair_id": item["pair_id"], "label": row["label"], "reason": row["reason"]}
        for item, row in zip(batch, rows, strict=True)
    ]


def _contract_request(batch: Sequence[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "request_kind": "security_neutral_functional_contract_extraction",
        "outcomes_or_arm_labels_included": False,
        "tasks": [
            {
                "item_index": index,
                "language": item["language"],
                "source_prompt": item["source_prompt"],
            }
            for index, item in enumerate(batch, start=1)
        ],
    }


def _contract_review_request(batch: Sequence[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "request_kind": "blind_functional_contract_quality_review",
        "cwe_arm_or_outcomes_included": False,
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


def _parse_contract_reviews(
    raw: bytes, batch: Sequence[dict[str, Any]]
) -> list[dict[str, Any]]:
    value = _json_object(raw)
    if set(value) != {"reviews"}:
        raise CurationError("contract-review response keys are not exact")
    rows = _last_by_index(_rows(value["reviews"], "contract reviews"), len(batch), "review")
    required = {
        "item_index",
        "contract_status",
        "functional_evaluability",
        "issue_codes",
        "reason",
    }
    frozen = []
    for row, item in zip(rows, batch, strict=True):
        if set(row) != required:
            raise CurationError("contract-review keys are invalid")
        status = row["contract_status"]
        evaluability = row["functional_evaluability"]
        issues = row["issue_codes"]
        if status not in _CONTRACT_REVIEW_STATUS or evaluability not in _FUNCTIONAL_EVALUABILITY:
            raise CurationError("contract-review status is invalid")
        if (
            not isinstance(issues, list)
            or not issues
            or len(issues) > 6
            or len(set(issues)) != len(issues)
            or any(issue not in _CONTRACT_ISSUES for issue in issues)
            or ((status == "faithful") != (issues == ["none"]))
        ):
            raise CurationError("contract-review issue codes are invalid")
        _bounded(row["reason"], 2000, "contract-review reason")
        frozen.append(
            {
                "cluster_id": item["cluster_id"],
                "contract_status": status,
                "functional_evaluability": evaluability,
                "issue_codes": issues,
                "reason": row["reason"],
            }
        )
    return frozen


def _parse_contracts(raw: bytes, batch: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    value = _json_object(raw)
    if set(value) != {"contracts"}:
        raise CurationError("contract response keys are not exact")
    rows = _rows(value["contracts"], "contracts")
    rows = _last_by_index(rows, len(batch), "contract response")
    keys = {
        "item_index",
        "resolution_status",
        "entrypoint",
        "requirements",
        "inputs",
        "outputs",
        "side_effects",
        "environment_dependencies",
        "reason",
    }
    for row, source in zip(rows, batch, strict=True):
        if "language" in row:
            if row["language"] != source["language"]:
                raise CurationError("contract response language does not match the request")
            row.pop("language")
        if set(row) != keys:
            raise CurationError("contract keys are invalid")
        if row["resolution_status"] not in _RESOLUTION:
            raise CurationError("contract resolution status is invalid")
        if row["entrypoint"] is not None:
            _bounded(row["entrypoint"], 500, "entrypoint")
        for name in (
            "requirements",
            "inputs",
            "outputs",
            "side_effects",
            "environment_dependencies",
        ):
            values = row[name]
            if not isinstance(values, list) or len(values) > 12:
                raise CurationError(f"{name} must contain at most twelve items")
            for item in values:
                _bounded(item, 1000, name)
        if row["resolution_status"] == "resolved" and not row["requirements"]:
            raise CurationError("resolved contracts require at least one requirement")
        _bounded(row["reason"], 1000, "contract reason")
    return [
        {
            **{key: value for key, value in row.items() if key != "item_index"},
            "record_id": item["record_id"],
            "source_prompt_sha256": item["source_prompt_sha256"],
        }
        for item, row in zip(batch, rows, strict=True)
    ]


def _load_existing_contracts(
    source: Path | None,
    items: Sequence[dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], dict[str, Any] | None]:
    if source is None:
        return {}, None
    root = source.resolve()
    verify_bundle(root)
    report = _object(read_json(root / "report.json"), "existing contract report")
    rows = _rows(read_json(root / "functional-contracts.json"), "existing contracts")
    if report.get("status") != "FUNCTIONAL_CONTRACTS_FROZEN":
        raise CurationError("existing contracts are not a frozen contract bundle")
    if report.get("contract_count") != len(rows):
        raise CurationError("existing contract report count does not match its rows")
    expected = {item["record_id"]: item for item in items}
    seen: set[str] = set()
    reused: dict[str, dict[str, Any]] = {}
    required_keys = {
        "cluster_id",
        "contract_id",
        "entrypoint",
        "environment_dependencies",
        "inputs",
        "outputs",
        "reason",
        "record_id",
        "requirements",
        "resolution_status",
        "side_effects",
        "source_prompt_sha256",
    }
    for row in rows:
        if set(row) != required_keys:
            raise CurationError("existing contract keys are invalid")
        record_id = row["record_id"]
        if not isinstance(record_id, str) or record_id in seen:
            raise CurationError("existing contract record IDs are invalid or duplicated")
        seen.add(record_id)
        old_core = {key: value for key, value in row.items() if key != "contract_id"}
        if row["contract_id"] != content_id("cluster_contract_", old_core):
            raise CurationError("existing contract content identity is invalid")
        if record_id not in expected:
            continue
        if row["source_prompt_sha256"] != expected[record_id]["source_prompt_sha256"]:
            raise CurationError("existing contract source prompt does not match the current record")
        reused[record_id] = {
            key: value for key, value in row.items() if key not in {"cluster_id", "contract_id"}
        }
    return reused, {
        "bundle_sha256": bundle_digest(root),
        "source_contract_count": len(rows),
        "reused_contract_count": len(reused),
    }


def _freeze_clusters(
    prepared: Path,
    candidates: Path,
    records: list[dict[str, Any]],
    decisions: list[dict[str, Any]],
    output: Path,
    plan: dict[str, Any],
) -> dict[str, Any]:
    record_by_id = {item["record_id"]: item for item in records}
    parent = {record_id: record_id for record_id in record_by_id}

    def find(value: str) -> str:
        while parent[value] != value:
            parent[value] = parent[parent[value]]
            value = parent[value]
        return value

    def union(left: str, right: str) -> bool:
        left_root, right_root = find(left), find(right)
        if left_root == right_root:
            return False
        keep, drop = min(left_root, right_root), max(left_root, right_root)
        parent[drop] = keep
        return True

    edges: list[dict[str, Any]] = []
    for cluster in _rows(read_json(prepared / "provisional-clusters.json"), "exact clusters"):
        members = cluster["record_ids"]
        for member in members[1:]:
            applied = union(members[0], member)
            edges.append(
                {
                    "left": members[0],
                    "right": member,
                    "evidence": "exact_prompt",
                    "applied": applied,
                }
            )
    lineage: dict[str, list[str]] = defaultdict(list)
    for record in records:
        if record["source_lineage_family"] == "securityeval":
            key = str(record["source_item_id"]).removeprefix("SecEvalBase:")
            lineage[key].append(record["record_id"])
    for key, members in sorted(lineage.items()):
        for member in members[1:]:
            applied = union(members[0], member)
            edges.append(
                {
                    "left": members[0],
                    "right": member,
                    "evidence": f"lineage:{key}",
                    "applied": applied,
                }
            )
    pair_by_id = {
        item["pair_id"]: item
        for item in _rows(read_json(candidates / "dedup-candidates.json"), "candidates")
    }
    diagnostic_edges = []
    for decision in decisions:
        pair = pair_by_id[decision["pair_id"]]
        left, right = pair["left_record_id"], pair["right_record_id"]
        if decision["label"] in {"same_cluster", "uncertain"}:
            diagnostic_edges.append(
                {
                    "pair_id": pair["pair_id"],
                    "left": left,
                    "right": right,
                    "lexical_jaccard": pair["lexical_jaccard"],
                    "label": decision["label"],
                    "reason": decision["reason"],
                    "applied_to_cluster": False,
                    "purpose": "diagnostic_only",
                }
            )
    diagnostic_edges.sort(key=lambda item: item["pair_id"])
    components: dict[str, list[str]] = defaultdict(list)
    for record_id in sorted(record_by_id):
        components[find(record_id)].append(record_id)
    clusters = []
    for members in components.values():
        members = sorted(members)
        values = [record_by_id[item] for item in members]
        languages = {item["language"] for item in values}
        if len(languages) != 1:
            raise CurationError("a semantic component crossed language blocks")
        representative = min(
            values,
            key=lambda item: (not bool(item["source_test_references"]), item["record_id"]),
        )
        language = next(iter(languages))
        cwes = sorted({item["cwe"] for item in values})
        core = {"record_ids": members, "language": language, "cwes": cwes}
        clusters.append(
            {
                "cluster_id": content_id("semantic_cluster_", core),
                "record_ids": members,
                "representative_record_id": representative["record_id"],
                "language": language,
                "cwes": cwes,
                "cwe_label_conflict": len(cwes) > 1,
            }
        )
    clusters.sort(key=lambda item: item["cluster_id"])
    labels = Counter(item["label"] for item in decisions)
    sizes = Counter(len(item["record_ids"]) for item in clusters)
    report = {
        "schema_version": "1.0",
        "status": "SEMANTIC_CLUSTERS_FROZEN",
        "prepared_bundle_sha256": plan["prepared_bundle_sha256"],
        "candidates_bundle_sha256": plan["candidates_bundle_sha256"],
        "record_count": len(records),
        "adjudicated_pair_count": len(decisions),
        "decision_counts": dict(sorted(labels.items())),
        "cluster_assembly_rule": _CLUSTER_ASSEMBLY_RULE,
        "merge_evidence_edge_count": len(edges),
        "merge_edge_count": sum(bool(item["applied"]) for item in edges),
        "diagnostic_positive_edge_count": len(diagnostic_edges),
        "llm_merge_edge_count": 0,
        "semantic_cluster_count": len(clusters),
        "cluster_size_counts": {str(key): value for key, value in sorted(sizes.items())},
        "largest_cluster_size": max(sizes),
        "semantic_clustering_complete": len(decisions) == plan["candidate_pair_count"],
        "outcomes_or_arm_labels_used": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(
        output,
        {
            "semantic-decisions.json": decisions,
            "merge-edges.json": edges,
            "diagnostic-semantic-edges.json": diagnostic_edges,
            "semantic-clusters.json": clusters,
            "report.json": report,
        },
    )
    return report


def _batches(
    items: Sequence[dict[str, Any]],
    identity: str,
    maximum_items: int,
    size: Callable[[dict[str, Any]], int],
) -> list[list[dict[str, Any]]]:
    batches: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    characters = 0
    seen: set[str] = set()
    for item in items:
        item_id = item[identity]
        if item_id in seen:
            raise CurationError(f"duplicate curation item: {item_id}")
        seen.add(item_id)
        item_size = size(item)
        if current and (len(current) >= maximum_items or characters + item_size > MAX_BATCH_CHARS):
            batches.append(current)
            current, characters = [], 0
        current.append(item)
        characters += item_size
    if current:
        batches.append(current)
    return batches


def _progress(
    stage: str, batch_count: int, items: list[dict[str, Any]], complete: bool
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "status": f"{stage}_{'COMPLETE' if complete else 'IN_PROGRESS'}",
        "batch_count": batch_count,
        "completed_item_count": len(items),
        "complete": complete,
    }


def _pair_chars(item: dict[str, Any]) -> int:
    return len(item["left_prompt"]) + len(item["right_prompt"])


def _contract_chars(item: dict[str, Any]) -> int:
    return len(item["source_prompt"])


def _contract_review_chars(item: dict[str, Any]) -> int:
    return len(item["source_prompt"]) + len(json.dumps(item["contract"], ensure_ascii=False))


def _deterministic_contract_issues(contract: Mapping[str, Any]) -> list[str]:
    requirements = contract.get("requirements")
    if not isinstance(requirements, list):
        raise CurationError("contract requirements are invalid")
    if any(
        _is_response_format_requirement(requirement)
        for requirement in requirements
        if isinstance(requirement, str)
    ):
        return ["response_format_instruction_leak"]
    return []


def _is_response_format_requirement(requirement: str) -> bool:
    return any(marker in requirement.lower() for marker in _RESPONSE_FORMAT_MARKERS)


def _json_object(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise CurationError("provider response is not strict JSON") from None
    return _object(value, "provider response")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            if type(value[key]) is not type(item) or value[key] != item:
                raise ValueError("conflicting duplicate JSON key")
            continue
        value[key] = item
    return value


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise CurationError(f"{name} must be an object")
    return value


def _rows(value: Any, name: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise CurationError(f"{name} must be a list")
    return [_object(item, name) for item in value]


def _bounded(value: Any, maximum: int, name: str) -> None:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > maximum
    ):
        raise CurationError(f"{name} must be trimmed text no longer than {maximum} characters")


def _last_by_index(rows: list[dict[str, Any]], count: int, name: str) -> list[dict[str, Any]]:
    by_index: dict[int, dict[str, Any]] = {}
    for row in rows:
        index = row.get("item_index")
        if type(index) is not int or not 1 <= index <= count:
            raise CurationError(f"{name} contains an invalid item index")
        by_index[index] = row
    expected = set(range(1, count + 1))
    if set(by_index) != expected:
        raise CurationError(f"{name} does not cover every item index")
    return [by_index[index] for index in sorted(by_index)]


__all__ = [
    "CurationError",
    "assemble_semantic_clusters",
    "run_contract_curation",
    "run_contract_quality_review",
    "repair_response_format_contract_leaks",
    "run_semantic_curation",
]

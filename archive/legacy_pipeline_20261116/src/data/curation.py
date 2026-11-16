"""Deterministic task grouping from supplied source records and decisions."""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from prompt_mechanism_study.artifact_io import bundle_digest, read_json, verify_bundle, write_bundle
from prompt_mechanism_study.records import content_id

# The frozen provider twice returned only the first ten items from 24-item
# requests and later returned eight of ten on a mixed-language batch.  Five is
# the conservative closed-response unit used by both outcome-blind stages; a
# response still has to bind every supplied index or the batch is rejected.
_RESPONSE_FORMAT_MARKERS = (
    "only return code",
    "only return the code",
    "only output code",
    "only output the code",
    "output only code",
    "output only the code",
    "return only code",
    "return only the code",
    "no preamble or suffix",
    "without preamble or suffix",
    "without a preamble or suffix",
    "don't include any other information",
    "do not include any other information",
)
_CLUSTER_ASSEMBLY_RULE = "exact_prompt_and_frozen_lineage_only_v1"


class CurationError(RuntimeError):
    """A frozen-input, provider, or response-contract failure."""


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


def _is_response_format_requirement(requirement: str) -> bool:
    return any(marker in requirement.lower() for marker in _RESPONSE_FORMAT_MARKERS)


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise CurationError(f"{name} must be an object")
    return value


def _rows(value: Any, name: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise CurationError(f"{name} must be a list")
    return [_object(item, name) for item in value]


__all__ = ['assemble_semantic_clusters', '_is_response_format_requirement']

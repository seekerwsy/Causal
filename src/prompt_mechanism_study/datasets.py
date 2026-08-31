"""Outcome-blind normalization of external benchmark task sources."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path
from typing import Any

from prompt_mechanism_study.artifact_io import (
    bundle_digest,
    file_sha256,
    read_json,
    verify_bundle,
    write_bundle,
)
from prompt_mechanism_study.records import canonical_value, content_hash, content_id, require_text

_CWE = re.compile(r"(?i)cwe[-_ ]?0*(\d+)")
_SOURCE_INFO = {
    "sallm": {
        "version": "0159a63daed0a88f461bbd69dd1160893e394a67",
        "license": "Apache-2.0",
        "citation_url": "https://github.com/s2e-lab/SALLM",
    },
    "cweval": {
        "version": "e9a2a124c8c53679b6d8d27adfd2f6c40e7576d7",
        "license": "Apache-2.0",
        "citation_url": "https://github.com/Co1lin/CWEval",
    },
    "cyberseceval_instruct_prime": {
        "version": "sha256:2bbc433c91a625dd82fa2f9e71d94b7318e1b6bbb077987d058d71a80a022788",
        "license": "MIT",
        "citation_url": "https://github.com/meta-llama/PurpleLlama",
    },
    "llmseceval": {
        "version": "39e97f046dbb2c4c604d31b86f2a4d3d27827388",
        "license": "GPL-3.0",
        "citation_url": "https://github.com/tuhh-softsec/LLMSecEval",
    },
    "securityeval": {
        "version": "6f4fb70f782c6d47b02ea24341e8ef8c1eb04a6a",
        "license": "not-declared",
        "citation_url": "https://github.com/s2e-lab/SecurityEval",
    },
    "codesec_eval": {
        "version": "c3ffce09269f2d7b092888efe05d070b6fcb97f5",
        "license": "not-declared",
        "citation_url": "https://huggingface.co/datasets/JasonWang1/CodeSecEval",
    },
    "secodeplt": {
        "version": "1f3da9ee48e0046359903cba0cc48d03665f96d5",
        "license": "not-declared",
        "citation_url": "https://github.com/ucsb-mlsec/SeCodePLT",
    },
}

_CONTRACT_POLICY = {
    "schema_version": "1.0",
    "purpose": "extract a functional contract before code generation",
    "instruction": (
        "Act as a software requirements engineer. Extract only behavior explicitly "
        "required by the source prompt. Do not add security requirements, preferred "
        "implementations, or unstated edge cases."
    ),
    "required_response_fields": [
        "record_id",
        "source_prompt_sha256",
        "entrypoint",
        "requirements",
        "inputs",
        "outputs",
        "side_effects",
    ],
}


@dataclass(frozen=True, slots=True)
class DatasetRecord:
    source_dataset: str
    source_version: str
    source_item_id: str
    source_locator: str
    source_file_sha256: str
    source_record_sha256: str
    source_lineage_family: str
    language: str
    cwe: str
    prompt: str
    license_id: str
    citation_url: str
    source_test_references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in (
            "source_dataset",
            "source_version",
            "source_item_id",
            "source_locator",
            "source_lineage_family",
            "language",
            "cwe",
            "prompt",
            "license_id",
            "citation_url",
        ):
            require_text(getattr(self, name), name)
        for digest in (self.source_file_sha256, self.source_record_sha256):
            if len(digest) != 64 or any(
                character not in "0123456789abcdef" for character in digest
            ):
                raise ValueError("dataset digests must be lowercase SHA-256")
        if not self.cwe.startswith("CWE-"):
            raise ValueError("cwe must use canonical CWE-N form")
        if tuple(sorted(set(self.source_test_references))) != self.source_test_references:
            raise ValueError("source test references must be sorted and unique")

    @property
    def record_id(self) -> str:
        return content_id("dataset_record_", self)

    @property
    def prompt_sha256(self) -> str:
        return content_hash(self.prompt)


@dataclass(frozen=True, slots=True)
class DatasetExclusion:
    source_dataset: str
    source_locator: str
    reason: str

    def __post_init__(self) -> None:
        for name in ("source_dataset", "source_locator", "reason"):
            require_text(getattr(self, name), name)


@dataclass(frozen=True, slots=True)
class ProvisionalCluster:
    cluster_id: str
    prompt_sha256: str
    record_ids: tuple[str, ...]
    evidence: str


@dataclass(frozen=True, slots=True)
class ContractDecision:
    record_id: str
    semantic_contract_status: str
    source_test_status: str
    reason: str


@dataclass(frozen=True, slots=True)
class ContractRequest:
    record_id: str
    source_prompt_sha256: str
    language: str
    cwe: str
    source_prompt: str


@dataclass(frozen=True, slots=True)
class TaskContract:
    record_id: str
    source_prompt_sha256: str
    entrypoint: str | None
    requirements: tuple[str, ...]
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    side_effects: tuple[str, ...]

    def __post_init__(self) -> None:
        require_text(self.record_id, "record_id")
        if self.entrypoint is not None:
            require_text(self.entrypoint, "entrypoint")
        if not self.requirements or len(self.requirements) > 8:
            raise ValueError("requirements must contain 1 to 8 items")
        for values in (self.requirements, self.inputs, self.outputs, self.side_effects):
            if len(values) > 8 or any(
                not isinstance(value, str) or not value.strip() for value in values
            ):
                raise ValueError("contract lists must contain at most 8 non-empty strings")

    @property
    def contract_id(self) -> str:
        return content_id("task_contract_", self)


@dataclass(frozen=True, slots=True)
class DedupCandidate:
    pair_id: str
    left_record_id: str
    right_record_id: str
    language: str
    left_cwe: str
    right_cwe: str
    lexical_jaccard: float
    left_prompt: str
    right_prompt: str


@dataclass(frozen=True, slots=True)
class _Batch:
    source_dataset: str
    records: tuple[DatasetRecord, ...]
    exclusions: tuple[DatasetExclusion, ...]


def prepare_datasets(
    output: Path,
    *,
    sallm_root: Path | None = None,
    cweval_root: Path | None = None,
    cyberseceval_path: Path | None = None,
    llmseceval_root: Path | None = None,
    securityeval_root: Path | None = None,
    codeseceval_root: Path | None = None,
    secodeplt_root: Path | None = None,
    limit_per_source: int | None = None,
) -> dict[str, Any]:
    """Normalize configured sources without executing source or generated code."""

    if limit_per_source is not None and (
        type(limit_per_source) is not int or limit_per_source <= 0
    ):
        raise ValueError("limit_per_source must be a positive integer")
    configured: list[tuple[Callable[[Path], _Batch], Path]] = []
    if sallm_root is not None:
        configured.append((_load_sallm, sallm_root))
    if cweval_root is not None:
        configured.append((_load_cweval, cweval_root))
    if cyberseceval_path is not None:
        configured.append((_load_cyberseceval, cyberseceval_path))
    if llmseceval_root is not None:
        configured.append((_load_llmseceval, llmseceval_root))
    if securityeval_root is not None:
        configured.append((_load_securityeval, securityeval_root))
    if codeseceval_root is not None:
        configured.append((_load_codeseceval, codeseceval_root))
    if secodeplt_root is not None:
        configured.append((_load_secodeplt, secodeplt_root))
    if not configured:
        raise ValueError("at least one dataset source is required")

    batches = tuple(loader(path.resolve()) for loader, path in configured)
    records: list[DatasetRecord] = []
    source_reports = []
    for batch in batches:
        ordered = tuple(sorted(batch.records, key=lambda item: item.record_id))
        emitted = ordered[:limit_per_source] if limit_per_source is not None else ordered
        records.extend(emitted)
        source_reports.append(
            {
                "source_dataset": batch.source_dataset,
                "parsed_records": len(ordered),
                "emitted_records": len(emitted),
                "excluded_records": len(batch.exclusions),
            }
        )
    records.sort(key=lambda item: item.record_id)
    if len({item.record_id for item in records}) != len(records):
        raise ValueError("normalized dataset record identities are not unique")
    exclusions = tuple(
        sorted(
            (item for batch in batches for item in batch.exclusions),
            key=lambda item: (item.source_dataset, item.source_locator, item.reason),
        )
    )
    clusters = _exact_prompt_clusters(records)
    decisions = tuple(
        ContractDecision(
            item.record_id,
            "pending",
            "available" if item.source_test_references else "unavailable",
            (
                "semantic requirements must be extracted before generation; "
                + (
                    "source-native test references were found"
                    if item.source_test_references
                    else "no source-native test reference was imported"
                )
            ),
        )
        for item in records
    )
    semantic_status_counts = Counter(item.semantic_contract_status for item in decisions)
    source_test_status_counts = Counter(item.source_test_status for item in decisions)
    requests = tuple(
        ContractRequest(
            item.record_id,
            item.prompt_sha256,
            item.language,
            item.cwe,
            item.prompt,
        )
        for item in records
    )
    report = {
        "schema_version": "1.0",
        "status": "DATASET_PREP_COMPLETE",
        "record_count": len(records),
        "provisional_exact_cluster_count": len(clusters),
        "cross_record_exact_duplicate_count": sum(
            len(item.record_ids) - 1 for item in clusters if len(item.record_ids) > 1
        ),
        "excluded_record_count": len(exclusions),
        "semantic_contract_status_counts": dict(sorted(semantic_status_counts.items())),
        "source_test_status_counts": dict(sorted(source_test_status_counts.items())),
        "sources": sorted(source_reports, key=lambda item: item["source_dataset"]),
        "limit_per_source": limit_per_source,
        "semantic_clustering_complete": False,
        "final_population_frozen": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(
        output,
        {
            "records.json": [
                {
                    "record_id": item.record_id,
                    "prompt_sha256": item.prompt_sha256,
                    **canonical_value(item),
                }
                for item in records
            ],
            "provisional-clusters.json": [canonical_value(item) for item in clusters],
            "contract-decisions.json": [canonical_value(item) for item in decisions],
            "contract-policy.json": _CONTRACT_POLICY,
            "contract-requests.json": [canonical_value(item) for item in requests],
            "exclusions.json": [canonical_value(item) for item in exclusions],
            "report.json": report,
        },
    )
    return report


def freeze_contracts(prepared_root: Path, responses_path: Path, output: Path) -> dict[str, Any]:
    """Validate externally extracted contracts and freeze them without model calls."""

    verify_bundle(prepared_root)
    requests = read_json(prepared_root / "contract-requests.json")
    responses = read_json(responses_path)
    if not isinstance(requests, list) or not isinstance(responses, list):
        raise TypeError("contract requests and responses must be JSON lists")
    expected = {_text(item.get("record_id")): _object(item) for item in requests}
    if len(expected) != len(requests):
        raise ValueError("contract request IDs are not unique")
    contracts: list[TaskContract] = []
    seen: set[str] = set()
    required_keys = {
        "record_id",
        "source_prompt_sha256",
        "entrypoint",
        "requirements",
        "inputs",
        "outputs",
        "side_effects",
    }
    for value in responses:
        raw = _object(value)
        if set(raw) != required_keys:
            raise ValueError("contract response fields do not match the frozen schema")
        record_id = _text(raw.get("record_id"))
        if record_id in seen or record_id not in expected:
            raise ValueError("contract response ID is duplicate or unexpected")
        seen.add(record_id)
        request = expected[record_id]
        prompt_sha256 = _text(raw.get("source_prompt_sha256"))
        if prompt_sha256 != request["source_prompt_sha256"]:
            raise ValueError("contract response is bound to the wrong source prompt")
        entrypoint = raw.get("entrypoint")
        if entrypoint is not None and not isinstance(entrypoint, str):
            raise ValueError("entrypoint must be a string or null")
        contracts.append(
            TaskContract(
                record_id,
                prompt_sha256,
                entrypoint.strip() if isinstance(entrypoint, str) else None,
                _string_tuple(raw.get("requirements")),
                _string_tuple(raw.get("inputs")),
                _string_tuple(raw.get("outputs")),
                _string_tuple(raw.get("side_effects")),
            )
        )
    if seen != set(expected):
        raise ValueError("contract responses do not cover the frozen request set")
    contracts.sort(key=lambda item: item.record_id)
    report = {
        "schema_version": "1.0",
        "status": "TASK_CONTRACTS_FROZEN",
        "prepared_bundle_sha256": bundle_digest(prepared_root),
        "contract_policy_sha256": content_hash(read_json(prepared_root / "contract-policy.json")),
        "contract_count": len(contracts),
        "manual_sample_review_required": True,
        "scientific_claim_allowed": False,
    }
    write_bundle(
        output,
        {
            "task-contracts.json": [
                {"contract_id": item.contract_id, **canonical_value(item)} for item in contracts
            ],
            "report.json": report,
        },
    )
    return report


def prepare_dedup_candidates(
    prepared_root: Path,
    output: Path,
    *,
    minimum_jaccard: float = 0.35,
    max_neighbors_per_record: int = 3,
) -> dict[str, Any]:
    """Create outcome-blind candidate pairs for later semantic adjudication."""

    if not 0.0 <= minimum_jaccard <= 1.0:
        raise ValueError("minimum_jaccard must be between zero and one")
    if type(max_neighbors_per_record) is not int or max_neighbors_per_record <= 0:
        raise ValueError("max_neighbors_per_record must be a positive integer")
    verify_bundle(prepared_root)
    raw_records = read_json(prepared_root / "records.json")
    if not isinstance(raw_records, list):
        raise TypeError("prepared records must be a JSON list")
    blocks: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for value in raw_records:
        raw = _object(value)
        blocks[_text(raw.get("language"))].append(raw)
    qualified: list[tuple[float, str, str, dict[str, Any]]] = []
    for language, members in sorted(blocks.items()):
        for left, right in combinations(sorted(members, key=lambda item: item["record_id"]), 2):
            if left["prompt_sha256"] == right["prompt_sha256"]:
                continue
            score = _jaccard(
                _tokens(_text(left.get("prompt"))), _tokens(_text(right.get("prompt")))
            )
            if score < minimum_jaccard:
                continue
            core = {
                "left_record_id": left["record_id"],
                "right_record_id": right["record_id"],
                "language": language,
                "left_cwe": left["cwe"],
                "right_cwe": right["cwe"],
                "lexical_jaccard": score,
                "left_prompt": left["prompt"],
                "right_prompt": right["prompt"],
            }
            qualified.append((score, left["record_id"], right["record_id"], core))
    neighbors: dict[str, list[tuple[float, str, str]]] = defaultdict(list)
    for score, left_id, right_id, _ in qualified:
        neighbors[left_id].append((score, left_id, right_id))
        neighbors[right_id].append((score, left_id, right_id))
    selected: set[tuple[str, str]] = set()
    for entries in neighbors.values():
        ranked = sorted(entries, key=lambda item: (-item[0], item[1], item[2]))
        selected.update(
            (left_id, right_id) for _, left_id, right_id in ranked[:max_neighbors_per_record]
        )
    candidates = [
        DedupCandidate(content_id("dedup_pair_", core), **core)
        for _, left_id, right_id, core in qualified
        if (left_id, right_id) in selected
    ]
    candidates.sort(key=lambda item: item.pair_id)
    report = {
        "schema_version": "1.0",
        "status": "DEDUP_CANDIDATES_PREPARED",
        "prepared_bundle_sha256": bundle_digest(prepared_root),
        "minimum_jaccard": minimum_jaccard,
        "max_neighbors_per_record": max_neighbors_per_record,
        "retrieval_block": "language",
        "qualified_pair_count_before_neighbor_cap": len(qualified),
        "candidate_pair_count": len(candidates),
        "adjudication_required": True,
        "semantic_clustering_complete": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(
        output,
        {
            "dedup-candidates.json": [canonical_value(item) for item in candidates],
            "report.json": report,
        },
    )
    return report


def build_prospective_role_census(
    candidate_population_root: Path,
    clusters_root: Path,
    legacy_manifest_path: Path,
    output: Path,
    *,
    candidate_artifact: str = "ready-confirmatory-task-units.json",
    population_target_task_units: int = 240,
) -> dict[str, Any]:
    """Census an outcome-blind population before any prospective role split.

    This step deliberately does not assign ``QUAL_DEV``, ``QUAL_ACCEPT``,
    ``DISCOVERY``, or ``CONFIRMATION``.  It closes exact and diagnostic
    near-duplicate leakage against every historical ``LEGACY_ONLY`` task and
    emits the remaining unexposed population on which sample-size and role
    allocation decisions can later be made.
    """

    if (
        type(population_target_task_units) is not int
        or population_target_task_units <= 0
    ):
        raise ValueError("population_target_task_units must be positive")
    verify_bundle(candidate_population_root)
    verify_bundle(clusters_root)
    candidates = read_json(candidate_population_root / candidate_artifact)
    clusters = read_json(clusters_root / "semantic-clusters.json")
    diagnostic_edges = read_json(
        clusters_root / "diagnostic-semantic-edges.json"
    )
    legacy_manifest = read_json(legacy_manifest_path)
    if not isinstance(candidates, list) or not candidates:
        raise TypeError("candidate population must be a non-empty JSON list")
    if not isinstance(clusters, list) or not isinstance(diagnostic_edges, list):
        raise TypeError("semantic-cluster census inputs must be JSON lists")
    if not isinstance(legacy_manifest, dict):
        raise TypeError("legacy role manifest must be a JSON object")

    candidate_by_task: dict[str, dict[str, Any]] = {}
    required_candidate_fields = {
        "arms_or_outcomes_used",
        "blocker_codes",
        "candidate_status",
        "final_dataset_status",
        "language",
        "mechanism_realization_id",
        "oracle_profile_id",
        "primary_cwe",
        "representative_record_id",
        "source_dataset",
        "source_lineage_family",
        "task_unit_id",
    }
    for value in candidates:
        row = _object(value)
        if not required_candidate_fields <= set(row):
            raise ValueError("candidate population row is missing census fields")
        task_unit_id = _text(row.get("task_unit_id"))
        if task_unit_id in candidate_by_task:
            raise ValueError("candidate task-unit identities are duplicated")
        if (
            row.get("arms_or_outcomes_used") is not False
            or row.get("candidate_status") != "READY_CONFIRMATORY"
            or row.get("final_dataset_status") != "INCLUDED_FINAL_DATASET"
            or row.get("language") != "python"
            or row.get("blocker_codes") != []
        ):
            raise ValueError(
                "prospective census accepts only outcome-blind ready Python tasks"
            )
        candidate_by_task[task_unit_id] = row

    cluster_by_record: dict[str, str] = {}
    cluster_ids: set[str] = set()
    for value in clusters:
        cluster = _object(value)
        cluster_id = _text(cluster.get("cluster_id"))
        record_ids = cluster.get("record_ids")
        if (
            cluster_id in cluster_ids
            or not isinstance(record_ids, list)
            or not record_ids
        ):
            raise ValueError("semantic cluster is duplicated or empty")
        cluster_ids.add(cluster_id)
        for record_id in record_ids:
            record_id = _text(record_id)
            if record_id in cluster_by_record:
                raise ValueError("a source record belongs to multiple task units")
            cluster_by_record[record_id] = cluster_id
    if not set(candidate_by_task) <= cluster_ids:
        raise ValueError("candidate population is not covered by semantic clusters")

    parent = {cluster_id: cluster_id for cluster_id in cluster_ids}

    def find(value: str) -> str:
        while parent[value] != value:
            parent[value] = parent[parent[value]]
            value = parent[value]
        return value

    def union(left: str, right: str) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            keep, drop = min(left_root, right_root), max(left_root, right_root)
            parent[drop] = keep

    for value in diagnostic_edges:
        edge = _object(value)
        if edge.get("label") not in {"same_cluster", "uncertain"}:
            raise ValueError("diagnostic near-duplicate edge has an invalid label")
        left = cluster_by_record.get(edge.get("left"))
        right = cluster_by_record.get(edge.get("right"))
        if left is None or right is None:
            raise ValueError("diagnostic near-duplicate edge leaves the cluster universe")
        union(left, right)

    component_members: dict[str, list[str]] = defaultdict(list)
    for cluster_id in sorted(cluster_ids):
        component_members[find(cluster_id)].append(cluster_id)
    group_by_cluster = {
        cluster_id: content_id("near_duplicate_group_", tuple(members))
        for members in component_members.values()
        for cluster_id in members
    }

    legacy_task_events: dict[str, set[str]] = defaultdict(set)
    legacy_task_data_ids: dict[str, set[str]] = defaultdict(set)
    for value in legacy_manifest.get("bindings", []):
        binding = _object(value)
        if binding.get("data_role") != "LEGACY_ONLY":
            raise ValueError("census input may contain only frozen legacy bindings")
        data_id = _text(binding.get("data_id"))
        events = binding.get("exposure_history_applies_to_all_task_units")
        lineage = binding.get("task_unit_source_lineage")
        if not isinstance(events, list) or not isinstance(lineage, dict):
            raise ValueError("legacy binding lacks exposure or task provenance")
        for task_unit_id in lineage:
            task_unit_id = _text(task_unit_id)
            legacy_task_data_ids[task_unit_id].add(data_id)
            legacy_task_events[task_unit_id].update(_text(item) for item in events)

    legacy_groups: dict[str, set[str]] = defaultdict(set)
    for task_unit_id in legacy_task_events:
        group_id = (
            group_by_cluster[task_unit_id]
            if task_unit_id in group_by_cluster
            else content_id("near_duplicate_group_", (task_unit_id,))
        )
        legacy_groups[group_id].add(task_unit_id)

    rows = []
    exact_overlap_count = 0
    near_duplicate_only_overlap_count = 0
    for task_unit_id, source in sorted(candidate_by_task.items()):
        group_id = group_by_cluster[task_unit_id]
        exact_legacy_ids = tuple(sorted(legacy_task_data_ids.get(task_unit_id, ())))
        near_legacy_tasks = tuple(sorted(legacy_groups.get(group_id, ())))
        exact_overlap = bool(exact_legacy_ids)
        near_duplicate_overlap = bool(near_legacy_tasks)
        exact_overlap_count += exact_overlap
        near_duplicate_only_overlap_count += near_duplicate_overlap and not exact_overlap
        exclusion_reasons = []
        exposure_history = set(legacy_task_events.get(task_unit_id, ()))
        if exact_overlap:
            exclusion_reasons.append("exact_task_unit_in_legacy_only")
        elif near_duplicate_overlap:
            exclusion_reasons.append("near_duplicate_group_intersects_legacy_only")
            exposure_history.add("near_duplicate_of_legacy_exposed_task")
        rows.append(
            {
                "task_unit_id": task_unit_id,
                "near_duplicate_group_id": group_id,
                "representative_record_id": source["representative_record_id"],
                "source_dataset": source["source_dataset"],
                "source_lineage_id": (
                    f"{source['source_dataset']}:{source['source_lineage_family']}"
                ),
                "primary_cwe": source["primary_cwe"],
                "mechanism_realization_id": source["mechanism_realization_id"],
                "oracle_profile_id": source["oracle_profile_id"],
                "exposure_history": sorted(exposure_history),
                "legacy_data_ids": list(exact_legacy_ids),
                "legacy_near_duplicate_task_unit_ids": list(near_legacy_tasks),
                "prospective_role_eligible": not exclusion_reasons,
                "prospective_exclusion_reasons": exclusion_reasons,
                "arms_or_outcomes_used": False,
            }
        )

    available = sum(bool(row["prospective_role_eligible"]) for row in rows)
    report: dict[str, Any] = {
        "schema_version": "1.0",
        "status": "PROSPECTIVE_ROLE_CENSUS_COMPLETE_ROLE_ALLOCATION_BLOCKED",
        "candidate_task_units": len(rows),
        "prospective_unexposed_task_units": available,
        "legacy_exact_overlap_count": exact_overlap_count,
        "legacy_near_duplicate_only_overlap_count": near_duplicate_only_overlap_count,
        "population_target_task_units": population_target_task_units,
        "population_target_met": available >= population_target_task_units,
        "role_assignment_frozen": False,
        "formal_use_authorized": False,
        "unassigned_roles": [
            "QUAL_DEV",
            "QUAL_ACCEPT",
            "DISCOVERY",
            "CONFIRMATION",
        ],
        "candidate_population_bundle_sha256": bundle_digest(
            candidate_population_root
        ),
        "candidate_artifact": candidate_artifact,
        "semantic_clusters_bundle_sha256": bundle_digest(clusters_root),
        "legacy_manifest_sha256": file_sha256(legacy_manifest_path),
        "near_duplicate_rule": (
            "semantic_task_unit_plus_same_or_uncertain_diagnostic_components_v1"
        ),
        "arms_or_outcomes_used": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(
        output,
        {
            "legacy-bindings.json": legacy_manifest.get("bindings", []),
            "task-units.json": rows,
            "report.json": report,
        },
    )
    return report


def _load_sallm(root: Path) -> _Batch:
    source = root / "Dataset/dataset.jsonl"
    payload = source.read_bytes()
    records: list[DatasetRecord] = []
    exclusions: list[DatasetExclusion] = []
    for line_number, line in enumerate(payload.decode("utf-8-sig").splitlines(), start=1):
        locator = f"Dataset/dataset.jsonl#L{line_number}"
        try:
            raw = _object(json.loads(line))
            item_id = _text(raw.get("id"))
            technique = _text(raw.get("technique"))
            origin = _text(raw.get("source"))
            prefix = f"{technique}_{origin}_"
            file_name = item_id[len(prefix) :] if item_id.startswith(prefix) else Path(item_id).name
            directory = root / "Dataset" / technique / origin
            stem = Path(file_name).stem
            tests = _existing_relative_paths(
                root,
                (
                    directory / f"test_{file_name}",
                    directory / f"{stem}_Dockerfile",
                    directory / f"{stem}_requirements.txt",
                ),
            )
            records.append(
                _record(
                    "sallm",
                    item_id,
                    locator,
                    payload,
                    raw,
                    "python",
                    _canonical_cwe(item_id),
                    _text(raw.get("prompt")),
                    tests,
                )
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            exclusions.append(DatasetExclusion("sallm", locator, type(error).__name__))
    return _Batch("sallm", tuple(records), tuple(exclusions))


def _load_cweval(root: Path) -> _Batch:
    records: list[DatasetRecord] = []
    exclusions: list[DatasetExclusion] = []
    for path in sorted((root / "benchmark").rglob("*_task.*")):
        locator = path.relative_to(root).as_posix()
        try:
            payload = path.read_bytes()
            text = payload.decode("utf-8-sig")
            prompt = _before_solution_marker(text)
            language = _language(path.parent.name)
            test_path = path.with_name(path.stem.removesuffix("_task") + "_test.py")
            records.append(
                _record(
                    "cweval",
                    locator,
                    locator,
                    payload,
                    {"path": locator, "prompt": prompt},
                    language,
                    _canonical_cwe(path.name),
                    prompt,
                    _existing_relative_paths(root, (test_path,)),
                )
            )
        except (KeyError, TypeError, UnicodeDecodeError, ValueError) as error:
            exclusions.append(DatasetExclusion("cweval", locator, type(error).__name__))
    return _Batch("cweval", tuple(records), tuple(exclusions))


def _load_cyberseceval(path: Path) -> _Batch:
    payload = path.read_bytes()
    raw_rows = json.loads(payload.decode("utf-8-sig"))
    if not isinstance(raw_rows, list):
        raise TypeError("CyberSecEval source must be a JSON list")
    records: list[DatasetRecord] = []
    exclusions: list[DatasetExclusion] = []
    for index, value in enumerate(raw_rows, start=1):
        locator = f"{path.name}#item:{index}"
        try:
            raw = _object(value)
            source_item = ":".join(
                (
                    _text(raw.get("repo")),
                    _text(raw.get("file_path")),
                    str(raw.get("line_number")),
                    _text(raw.get("pattern_id")),
                )
            )
            records.append(
                _record(
                    "cyberseceval_instruct_prime",
                    source_item,
                    locator,
                    payload,
                    raw,
                    _language(_text(raw.get("language"))),
                    _canonical_cwe(_text(raw.get("cwe_identifier"))),
                    _text(raw.get("test_case_prompt")),
                    (),
                )
            )
        except (KeyError, TypeError, ValueError) as error:
            exclusions.append(
                DatasetExclusion("cyberseceval_instruct_prime", locator, type(error).__name__)
            )
    return _Batch("cyberseceval_instruct_prime", tuple(records), tuple(exclusions))


def _load_llmseceval(root: Path) -> _Batch:
    source = root / "Dataset/LLMSecEval-Prompts_dataset.json"
    payload = source.read_bytes()
    raw_rows = json.loads(payload.decode("utf-8-sig"))
    if not isinstance(raw_rows, list):
        raise TypeError("LLMSecEval source must be a JSON list")
    records: list[DatasetRecord] = []
    exclusions: list[DatasetExclusion] = []
    for index, value in enumerate(raw_rows, start=1):
        locator = f"Dataset/LLMSecEval-Prompts_dataset.json#item:{index}"
        try:
            raw = _object(value)
            fixed = raw.get("Manually-fixed NL Prompt")
            prompt = (
                fixed
                if isinstance(fixed, str) and fixed.strip()
                else raw.get("LLM-generated NL Prompt")
            )
            item_id = str(raw.get("Prompt ID") or raw.get("Filename") or index)
            records.append(
                _record(
                    "llmseceval",
                    item_id,
                    locator,
                    payload,
                    raw,
                    _language(_text(raw.get("Language"))),
                    _canonical_cwe(_text(raw.get("Prompt ID"))),
                    _text(prompt),
                    (),
                )
            )
        except (KeyError, TypeError, ValueError) as error:
            exclusions.append(DatasetExclusion("llmseceval", locator, type(error).__name__))
    return _Batch("llmseceval", tuple(records), tuple(exclusions))


def _load_securityeval(root: Path) -> _Batch:
    source = root / "dataset.jsonl"
    payload = source.read_bytes()
    records: list[DatasetRecord] = []
    exclusions: list[DatasetExclusion] = []
    for line_number, line in enumerate(payload.decode("utf-8-sig").splitlines(), start=1):
        locator = f"dataset.jsonl#L{line_number}"
        try:
            raw = _object(json.loads(line))
            item_id = _text(raw.get("ID"))
            records.append(
                _record(
                    "securityeval",
                    item_id,
                    locator,
                    payload,
                    raw,
                    "python",
                    _canonical_cwe(item_id),
                    _text(raw.get("Prompt")),
                    (),
                )
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            exclusions.append(DatasetExclusion("securityeval", locator, type(error).__name__))
    return _Batch("securityeval", tuple(records), tuple(exclusions))


def _load_codeseceval(root: Path) -> _Batch:
    records: list[DatasetRecord] = []
    exclusions: list[DatasetExclusion] = []
    sources = (
        (root / "data/SecEvalBase/test.jsonl", "securityeval"),
        (root / "data/SecEvalPlus/test.jsonl", "codesec_eval_plus"),
    )
    for source, lineage in sources:
        payload = source.read_bytes()
        relative = source.relative_to(root).as_posix()
        for line_number, line in enumerate(payload.decode("utf-8-sig").splitlines(), start=1):
            locator = f"{relative}#L{line_number}"
            try:
                raw = _object(json.loads(line))
                item_id = _text(raw.get("ID"))
                test = raw.get("Test")
                test_references = (
                    (f"{locator}#field:Test",) if isinstance(test, str) and test.strip() else ()
                )
                records.append(
                    _record(
                        "codesec_eval",
                        f"{source.parent.name}:{item_id}",
                        locator,
                        payload,
                        raw,
                        "python",
                        _canonical_cwe(item_id),
                        _text(raw.get("Problem")),
                        test_references,
                        source_lineage_family=lineage,
                    )
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                exclusions.append(DatasetExclusion("codesec_eval", locator, type(error).__name__))
    return _Batch("codesec_eval", tuple(records), tuple(exclusions))


def _load_secodeplt(root: Path) -> _Batch:
    records: list[DatasetRecord] = []
    exclusions: list[DatasetExclusion] = []
    pattern = "generate_dataset/data/*/succeed_python_list.json"
    for source in sorted(root.glob(pattern)):
        payload = source.read_bytes()
        relative = source.relative_to(root).as_posix()
        raw_rows = json.loads(payload.decode("utf-8-sig"))
        if not isinstance(raw_rows, list):
            raise TypeError(f"SeCodePLT source is not a JSON list: {relative}")
        for index, value in enumerate(raw_rows, start=1):
            locator = f"{relative}#item:{index}"
            try:
                if not isinstance(value, str) or not value.strip():
                    raise TypeError("SeCodePLT task must be a non-empty string")
                metadata = _secode_metadata(value)
                task = _object(metadata.get("task_description"))
                function_name = _text(task.get("function_name"))
                cve = metadata.get("CVE_ID")
                source_id = cve.strip() if isinstance(cve, str) and cve.strip() else relative
                item_id = f"{source_id}:{function_name}:{index}"
                tests = _marker_text(value, "TESTCASES")
                test_references = (f"{locator}#section:TESTCASES",) if tests.strip() else ()
                records.append(
                    _record(
                        "secodeplt",
                        item_id,
                        locator,
                        payload,
                        {"task": value},
                        "python",
                        _canonical_cwe(_text(metadata.get("CWE_ID"))),
                        _secode_functional_prompt(task),
                        test_references,
                    )
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                exclusions.append(DatasetExclusion("secodeplt", locator, type(error).__name__))
    return _Batch("secodeplt", tuple(records), tuple(exclusions))


def _record(
    source_dataset: str,
    source_item_id: str,
    source_locator: str,
    source_payload: bytes,
    raw_record: dict[str, Any],
    language: str,
    cwe: str,
    prompt: str,
    source_test_references: Iterable[str],
    *,
    source_lineage_family: str | None = None,
) -> DatasetRecord:
    info = _SOURCE_INFO[source_dataset]
    return DatasetRecord(
        source_dataset=source_dataset,
        source_version=info["version"],
        source_item_id=source_item_id.strip(),
        source_locator=source_locator,
        source_file_sha256=hashlib.sha256(source_payload).hexdigest(),
        source_record_sha256=content_hash(raw_record),
        source_lineage_family=source_lineage_family or source_dataset,
        language=language,
        cwe=cwe,
        prompt=prompt.strip().replace("\r\n", "\n").replace("\r", "\n"),
        license_id=info["license"],
        citation_url=info["citation_url"],
        source_test_references=tuple(sorted(set(source_test_references))),
    )


def _exact_prompt_clusters(records: Iterable[DatasetRecord]) -> tuple[ProvisionalCluster, ...]:
    groups: dict[str, list[str]] = defaultdict(list)
    for record in records:
        groups[record.prompt_sha256].append(record.record_id)
    clusters = []
    for prompt_sha256, member_ids in sorted(groups.items()):
        members = tuple(sorted(member_ids))
        clusters.append(
            ProvisionalCluster(
                content_id(
                    "provisional_cluster_",
                    {"prompt_sha256": prompt_sha256, "record_ids": members},
                ),
                prompt_sha256,
                members,
                "exact_prompt" if len(members) > 1 else "singleton",
            )
        )
    return tuple(sorted(clusters, key=lambda item: item.cluster_id))


def _marker_text(value: str, marker: str) -> str:
    start = f"## START {marker} ##"
    end = f"## END {marker} ##"
    if start not in value or end not in value:
        raise ValueError(f"SeCodePLT task is missing {marker} markers")
    return value.split(start, 1)[1].split(end, 1)[0].strip()


def _secode_metadata(value: str) -> dict[str, Any]:
    raw = _marker_text(value, "METADATA")
    try:
        return _object(json.loads(raw))
    except json.JSONDecodeError:
        repaired = re.sub(r",\s*([}\]])", r"\1", raw)
        return _object(json.loads(repaired))


def _secode_functional_prompt(task: dict[str, Any]) -> str:
    labels = (
        ("Task", "description"),
        ("Context", "context"),
        ("Arguments", "arguments"),
        ("Return", "return"),
        ("Raises", "raise"),
    )
    parts = []
    for label, key in labels:
        value = task.get(key)
        if isinstance(value, str) and value.strip() and value.strip().casefold() != "none":
            parts.append(f"{label}: {value.strip()}")
    if not parts:
        raise ValueError("SeCodePLT task has no functional description")
    return "\n".join(parts)


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise TypeError("contract list fields must be JSON arrays")
    items = tuple(item.strip() if isinstance(item, str) else "" for item in value)
    if any(not item for item in items) or len(set(items)) != len(items):
        raise ValueError("contract list fields must contain unique non-empty strings")
    return items


def _tokens(value: str) -> frozenset[str]:
    return frozenset(re.findall(r"[a-z0-9_]+", value.casefold()))


def _jaccard(left: frozenset[str], right: frozenset[str]) -> float:
    union = left | right
    return round(len(left & right) / len(union), 6) if union else 1.0


def _before_solution_marker(text: str) -> str:
    lines = text.replace("\r\n", "\n").replace("\r", "\n").splitlines()
    for index, line in enumerate(lines):
        if "BEGIN SOLUTION" in line:
            prompt = "\n".join(lines[:index]).strip()
            if prompt:
                return prompt
            break
    raise ValueError("CWEval task has no non-empty pre-solution prompt")


def _existing_relative_paths(root: Path, paths: Iterable[Path]) -> tuple[str, ...]:
    return tuple(sorted(path.relative_to(root).as_posix() for path in paths if path.is_file()))


def _canonical_cwe(value: str) -> str:
    normalized = value.strip()
    match = _CWE.search(normalized)
    if match is None and normalized.isdigit():
        return f"CWE-{int(normalized)}"
    if match is None:
        raise ValueError("CWE identifier is unavailable")
    return f"CWE-{int(match.group(1))}"


def _language(value: str) -> str:
    normalized = value.strip().casefold()
    aliases = {
        "py": "python",
        "python3": "python",
        "c++": "cpp",
        "js": "javascript",
        "c#": "csharp",
        "cs": "csharp",
    }
    normalized = aliases.get(normalized, normalized)
    require_text(normalized, "language")
    return normalized


def _object(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise TypeError("dataset record must be an object with string keys")
    return value


def _text(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("required dataset text is unavailable")
    return value.strip()


__all__ = [
    "ContractDecision",
    "ContractRequest",
    "DatasetExclusion",
    "DatasetRecord",
    "ProvisionalCluster",
    "build_prospective_role_census",
    "freeze_contracts",
    "prepare_dedup_candidates",
    "prepare_datasets",
]

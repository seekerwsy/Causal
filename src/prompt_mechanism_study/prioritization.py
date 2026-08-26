"""Outcome-blind discovery support, selector scores, and top-K slots."""

from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from prompt_mechanism_study.artifact_io import (
    bundle_digest,
    read_json,
    verify_bundle,
    write_bundle,
)
from prompt_mechanism_study.prompt_tsg import (
    QueryState,
    catalog_sha256,
    feature_state,
    load_catalog,
    prompt_tsg_from_record,
    query_context,
    validate_prompt_tsg,
)
from prompt_mechanism_study.records import content_id, require_text
from prompt_mechanism_study.representation import CandidateUniverse


@dataclass(frozen=True, slots=True)
class RankedCandidate:
    candidate_id: str
    score: float
    rank: int

    def __post_init__(self) -> None:
        require_text(self.candidate_id, "candidate_id")
        if type(self.score) not in {int, float} or not math.isfinite(float(self.score)):
            raise ValueError("score must be finite")
        if type(self.rank) is not int or self.rank <= 0:
            raise ValueError("rank must be positive")


@dataclass(frozen=True, slots=True)
class SelectionFreeze:
    universe_id: str
    selector_adapter_id: str
    top_k: int
    ranking: tuple[RankedCandidate, ...]

    def __post_init__(self) -> None:
        require_text(self.universe_id, "universe_id")
        require_text(self.selector_adapter_id, "selector_adapter_id")
        if type(self.top_k) is not int or not 1 <= self.top_k <= len(self.ranking):
            raise ValueError("top_k is outside the ranked candidate support")
        if tuple(item.rank for item in self.ranking) != tuple(range(1, len(self.ranking) + 1)):
            raise ValueError("ranking positions must be complete and canonical")
        if len({item.candidate_id for item in self.ranking}) != len(self.ranking):
            raise ValueError("ranking candidate ids must be unique")

    @property
    def selection_id(self) -> str:
        return content_id("selection_", self)

    @property
    def selected_candidate_ids(self) -> tuple[str, ...]:
        return tuple(item.candidate_id for item in self.ranking[: self.top_k])


def freeze_selection(
    universe: CandidateUniverse,
    scores: Mapping[str, float],
    *,
    selector_adapter_id: str,
    top_k: int,
) -> SelectionFreeze:
    candidate_ids = tuple(item.candidate_id for item in universe.candidates)
    if set(scores) != set(candidate_ids):
        raise ValueError("selector scores must bind every candidate exactly once")
    ordered = sorted(
        candidate_ids,
        key=lambda candidate_id: (-_score(scores[candidate_id]), candidate_id),
    )
    ranking = tuple(
        RankedCandidate(candidate_id, _score(scores[candidate_id]), rank)
        for rank, candidate_id in enumerate(ordered, start=1)
    )
    return SelectionFreeze(
        universe.universe_id,
        selector_adapter_id,
        top_k,
        ranking,
    )


def prepare_discovery_population(
    prepared_root: Path,
    clusters_root: Path,
    catalog_path: Path,
    output: Path,
    *,
    scopes: Mapping[str, str],
    language: str = "python",
) -> dict[str, object]:
    """Freeze one natural-Prompt census without reading arms or outcomes.

    ``scopes`` maps a CWE to exactly one catalog task family. Requiring this
    coordinate up front prevents a pre-TSG lexical guess from deciding which
    context query a record should enter.
    """

    verify_bundle(prepared_root)
    verify_bundle(clusters_root)
    if not scopes or any(
        not isinstance(cwe, str)
        or not cwe.strip()
        or not isinstance(task_family, str)
        or not task_family.strip()
        for cwe, task_family in scopes.items()
    ):
        raise ValueError("discovery scopes must map non-empty CWE and task-family strings")
    require_text(language, "language")
    catalog = load_catalog(catalog_path)
    available = {
        (query["cwe_id"], query["task_family"])
        for query in catalog["queries"]
    }
    requested = set(scopes.items())
    if not requested <= available:
        raise ValueError("a discovery scope has no catalog query")

    records = read_json(prepared_root / "records.json")
    clusters = read_json(clusters_root / "semantic-clusters.json")
    if not isinstance(records, list) or not isinstance(clusters, list):
        raise ValueError("discovery source bundles are invalid")
    record_by_id = {record.get("record_id"): record for record in records}
    if len(record_by_id) != len(records) or None in record_by_id:
        raise ValueError("prepared record identities are invalid")

    tasks = []
    for cluster in clusters:
        record = record_by_id.get(cluster.get("representative_record_id"))
        if record is None or record.get("language") != language:
            continue
        cwe = record.get("cwe")
        task_family = scopes.get(cwe)
        if task_family is None:
            continue
        prompt = record.get("prompt")
        cluster_id = cluster.get("cluster_id")
        if not isinstance(prompt, str) or not prompt.strip() or not isinstance(cluster_id, str):
            raise ValueError("discovery representative is incomplete")
        tasks.append(
            {
                "task_id": cluster_id,
                "task_unit_id": cluster_id,
                "record_id": record["record_id"],
                "prompt": prompt,
                "prompt_sha256": record["prompt_sha256"],
                "cwe": cwe,
                "task_family": task_family,
                "source_dataset": record["source_dataset"],
                "source_lineage_family": record["source_lineage_family"],
            }
        )
    tasks.sort(key=lambda item: item["task_unit_id"])
    if not tasks:
        raise ValueError("discovery population is empty")
    if len({task["task_unit_id"] for task in tasks}) != len(tasks):
        raise ValueError("discovery task units are duplicated")

    scope_counts = Counter((task["cwe"], task["task_family"]) for task in tasks)
    lineage_counts = Counter(task["source_lineage_family"] for task in tasks)
    report: dict[str, object] = {
        "schema_version": "1.0",
        "status": "DISCOVERY_POPULATION_FROZEN",
        "language": language,
        "task_units": len(tasks),
        "scope_counts": [
            {"cwe": cwe, "task_family": family, "task_units": count}
            for (cwe, family), count in sorted(scope_counts.items())
        ],
        "lineage_counts": dict(sorted(lineage_counts.items())),
        "prepared_bundle_sha256": bundle_digest(prepared_root),
        "clusters_bundle_sha256": bundle_digest(clusters_root),
        "catalog_sha256": catalog_sha256(catalog),
        "arms_or_outcomes_used": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(output, {"tasks.json": tasks, "report.json": report})
    return report


def audit_discovery_positivity(
    tasks_path: Path,
    graph_bundles: tuple[Path, ...],
    catalog_path: Path,
    output: Path,
    *,
    minimum_state_task_units: int = 30,
    minimum_shared_lineages: int = 2,
) -> dict[str, object]:
    """Audit natural feature support before any FCI or outcome is read."""

    if type(minimum_state_task_units) is not int or minimum_state_task_units <= 0:
        raise ValueError("minimum_state_task_units must be positive")
    if type(minimum_shared_lineages) is not int or minimum_shared_lineages <= 0:
        raise ValueError("minimum_shared_lineages must be positive")
    if not graph_bundles:
        raise ValueError("at least one Prompt TSG bundle is required")
    tasks = _task_records(tasks_path)
    if not tasks or len({task.get("task_id") for task in tasks}) != len(tasks):
        raise ValueError("discovery tasks are empty or duplicated")
    catalog = load_catalog(catalog_path)
    graphs = []
    graph_bundle_ids = []
    for bundle in graph_bundles:
        verify_bundle(bundle)
        graph_bundle_ids.append(bundle_digest(bundle))
        value = read_json(bundle / "graphs.json")
        if not isinstance(value, list):
            raise ValueError("Prompt TSG graph collection is invalid")
        graphs.extend(prompt_tsg_from_record(item) for item in value)
    graph_by_task = {graph.task_id: graph for graph in graphs}
    if len(graph_by_task) != len(graphs) or set(graph_by_task) != {
        task["task_id"] for task in tasks
    }:
        raise ValueError("Prompt TSG population does not exactly match discovery tasks")

    rows: list[dict[str, object]] = []
    for task in tasks:
        required = {
            "task_id",
            "task_unit_id",
            "prompt",
            "cwe",
            "task_family",
            "source_lineage_family",
        }
        if not required <= set(task):
            raise ValueError("a discovery task lacks required coordinates")
        graph = graph_by_task[task["task_id"]]
        validate_prompt_tsg(graph, prompt=task["prompt"], catalog=catalog)
        queries = [
            query
            for query in catalog["queries"]
            if query["cwe_id"] == task["cwe"]
            and query["task_family"] == task["task_family"]
        ]
        if not queries:
            raise ValueError("a discovery task has no catalog query")
        for query in queries:
            context = query_context(
                graph,
                query=query,
                cwe=task["cwe"],
                task_family=task["task_family"],
            ).state
            state = feature_state(graph, query["actionable_feature_id"])
            context_present = context is QueryState.PRESENT
            resolved_feature = state in {QueryState.PRESENT, QueryState.ABSENT}
            rows.append(
                {
                    "task_id": task["task_id"],
                    "task_unit_id": task["task_unit_id"],
                    "source_lineage_family": task["source_lineage_family"],
                    "cwe": task["cwe"],
                    "task_family": task["task_family"],
                    "query_id": query["query_id"],
                    "feature_id": query["actionable_feature_id"],
                    "context_state": context.value,
                    "source_feature_state": state.value,
                    "discovery_eligible": context_present and resolved_feature,
                    "confirm_add_source_eligible": context_present
                    and state is QueryState.ABSENT,
                    "confirm_remove_source_eligible": context_present
                    and state is QueryState.PRESENT,
                    "confirm_remove_eligible": False,
                    "neutral_counterpart_status": "not_attested",
                }
            )

    support = []
    for query_id in sorted({row["query_id"] for row in rows}):
        query_rows = [row for row in rows if row["query_id"] == query_id]
        context_rows = [row for row in query_rows if row["context_state"] == "present"]
        present = [row for row in context_rows if row["source_feature_state"] == "present"]
        absent = [row for row in context_rows if row["source_feature_state"] == "absent"]
        unresolved = [
            row for row in context_rows if row["source_feature_state"] == "unresolved"
        ]
        present_lineages = {row["source_lineage_family"] for row in present}
        absent_lineages = {row["source_lineage_family"] for row in absent}
        shared_lineages = present_lineages & absent_lineages
        reasons = []
        if len(present) < minimum_state_task_units:
            reasons.append("insufficient_present_support")
        if len(absent) < minimum_state_task_units:
            reasons.append("insufficient_absent_support")
        if len(shared_lineages) < minimum_shared_lineages:
            reasons.append("insufficient_source_lineage_overlap")
        first = query_rows[0]
        support.append(
            {
                "query_id": query_id,
                "feature_id": first["feature_id"],
                "cwe": first["cwe"],
                "task_family": first["task_family"],
                "task_units": len(query_rows),
                "context_present": len(context_rows),
                "feature_present": len(present),
                "feature_absent": len(absent),
                "feature_unresolved": len(unresolved),
                "present_lineages": sorted(present_lineages),
                "absent_lineages": sorted(absent_lineages),
                "shared_lineages": sorted(shared_lineages),
                "positivity_gate_passed": not reasons,
                "failure_reasons": reasons,
            }
        )

    passed = sum(item["positivity_gate_passed"] for item in support)
    report: dict[str, object] = {
        "schema_version": "1.0",
        "status": "POSITIVITY_GATE_PASSED" if passed else "POSITIVITY_GATE_FAILED",
        "task_units": len(tasks),
        "candidate_queries": len(support),
        "passed_queries": passed,
        "minimum_state_task_units": minimum_state_task_units,
        "minimum_shared_lineages": minimum_shared_lineages,
        "task_file_sha256": hashlib.sha256(tasks_path.read_bytes()).hexdigest(),
        "graph_bundle_sha256": sorted(graph_bundle_ids),
        "catalog_sha256": catalog_sha256(catalog),
        "arms_or_outcomes_used": False,
        "fci_executed": False,
        "scientific_claim_allowed": False,
    }
    write_bundle(
        output,
        {
            "report.json": report,
            "positivity-rows.json": rows,
            "support.json": support,
        },
    )
    return report


def _task_records(path: Path) -> list[dict[str, object]]:
    try:
        if path.suffix == ".jsonl":
            value = [
                json.loads(line)
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        else:
            value = read_json(path)
    except (OSError, UnicodeError, ValueError):
        raise ValueError("discovery task file is unreadable") from None
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ValueError("discovery task file must contain a list of objects")
    return value


def _score(value: float) -> float:
    if type(value) not in {int, float} or not math.isfinite(float(value)):
        raise ValueError("selector scores must be finite")
    return float(value)


__all__ = [
    "RankedCandidate",
    "SelectionFreeze",
    "audit_discovery_positivity",
    "freeze_selection",
    "prepare_discovery_population",
]

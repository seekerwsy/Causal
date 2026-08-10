from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher
import hashlib


CLUSTER_VERSION = "task-cluster-v1"


@dataclass(frozen=True, slots=True)
class ClusterItem:
    item_key: str
    source_id: str
    line_number: int
    record_id: str | None = None
    exact_prompt_sha256: str | None = None
    normalized_prompt_sha256: str | None = None
    prompt: str | None = None
    repository: str | None = None
    file_path: str | None = None


@dataclass(frozen=True, slots=True)
class ClusterEdge:
    left_item_key: str
    right_item_key: str
    evidence_type: str
    evidence_value: str


@dataclass(frozen=True, slots=True)
class ClusterAssignment:
    item_key: str
    cluster_id: str
    independence_resolved: bool


@dataclass(frozen=True, slots=True)
class ClusterResult:
    version: str
    assignments: tuple[ClusterAssignment, ...]
    edges: tuple[ClusterEdge, ...]
    unresolved_relations: tuple[ClusterEdge, ...]


class _UnionFind:
    def __init__(self, keys: list[str]) -> None:
        self.parent = {key: key for key in keys}

    def find(self, key: str) -> str:
        parent = self.parent[key]
        if parent != key:
            self.parent[key] = self.find(parent)
        return self.parent[key]

    def union(self, left: str, right: str) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return
        first, second = sorted((left_root, right_root))
        self.parent[second] = first


def _add_group_edges(
    groups: dict[str, list[ClusterItem]],
    evidence_type: str,
    union_find: _UnionFind,
    edges: list[ClusterEdge],
) -> None:
    for value, members in sorted(groups.items()):
        ordered = sorted(members, key=lambda item: item.item_key)
        for index, left in enumerate(ordered):
            for right in ordered[index + 1 :]:
                union_find.union(left.item_key, right.item_key)
                edges.append(
                    ClusterEdge(left.item_key, right.item_key, evidence_type, value)
                )


def _stable_cluster_id(members: list[ClusterItem]) -> str:
    coordinates = sorted(
        f"{item.source_id}:{item.line_number}:{item.item_key}" for item in members
    )
    digest = hashlib.sha256("\n".join(coordinates).encode("utf-8")).hexdigest()
    return f"cluster-{digest[:20]}"


def build_task_clusters(items: list[ClusterItem]) -> ClusterResult:
    ordered = sorted(items, key=lambda item: item.item_key)
    if len({item.item_key for item in ordered}) != len(ordered):
        raise ValueError("cluster item keys must be unique")
    union_find = _UnionFind([item.item_key for item in ordered])
    edges: list[ClusterEdge] = []

    identities: dict[str, list[ClusterItem]] = {}
    repositories: dict[str, list[ClusterItem]] = {}
    exact: dict[str, list[ClusterItem]] = {}
    normalized: dict[str, list[ClusterItem]] = {}
    for item in ordered:
        if item.record_id:
            identities.setdefault(f"{item.source_id}\0{item.record_id}", []).append(item)
        if item.repository and item.file_path:
            repositories.setdefault(f"{item.repository}\0{item.file_path}", []).append(item)
        if item.exact_prompt_sha256:
            exact.setdefault(item.exact_prompt_sha256, []).append(item)
        if item.normalized_prompt_sha256:
            normalized.setdefault(item.normalized_prompt_sha256, []).append(item)

    _add_group_edges(identities, "SOURCE_TASK_IDENTITY", union_find, edges)
    _add_group_edges(repositories, "REPOSITORY_FILE_COORDINATE", union_find, edges)
    _add_group_edges(exact, "EXACT_PROMPT_DIGEST", union_find, edges)
    _add_group_edges(normalized, "NORMALIZED_PROMPT_DIGEST", union_find, edges)

    unresolved: list[ClusterEdge] = []
    unresolved_keys: set[str] = set()
    for index, left in enumerate(ordered):
        if not left.prompt:
            continue
        for right in ordered[index + 1 :]:
            same_cluster = union_find.find(left.item_key) == union_find.find(
                right.item_key
            )
            if not right.prompt or same_cluster:
                continue
            similarity = SequenceMatcher(None, left.prompt, right.prompt, autojunk=False).ratio()
            if 0.88 <= similarity < 1.0:
                unresolved.append(
                    ClusterEdge(
                        left.item_key,
                        right.item_key,
                        "AMBIGUOUS_TEXT_SIMILARITY",
                        f"{similarity:.6f}",
                    )
                )
                unresolved_keys.update((left.item_key, right.item_key))

    groups: dict[str, list[ClusterItem]] = {}
    for item in ordered:
        groups.setdefault(union_find.find(item.item_key), []).append(item)
    cluster_ids = {
        root: _stable_cluster_id(members) for root, members in sorted(groups.items())
    }
    assignments = tuple(
        ClusterAssignment(
            item_key=item.item_key,
            cluster_id=cluster_ids[union_find.find(item.item_key)],
            independence_resolved=item.item_key not in unresolved_keys,
        )
        for item in ordered
    )
    return ClusterResult(
        version=CLUSTER_VERSION,
        assignments=assignments,
        edges=tuple(sorted(set(edges), key=repr)),
        unresolved_relations=tuple(sorted(unresolved, key=repr)),
    )

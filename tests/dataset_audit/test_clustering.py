from __future__ import annotations

from secaware.dataset_audit.clustering import ClusterItem, build_task_clusters
import secaware.dataset_audit.clustering as clustering_module


def _item(
    key: str,
    *,
    source: str = "source",
    record_id: str | None = None,
    exact: str | None = None,
    normalized: str | None = None,
    prompt: str | None = None,
    repository: str | None = None,
    file_path: str | None = None,
) -> ClusterItem:
    return ClusterItem(
        item_key=key,
        source_id=source,
        line_number=int(key.removeprefix("r")),
        record_id=record_id,
        exact_prompt_sha256=exact,
        normalized_prompt_sha256=normalized,
        prompt=prompt,
        repository=repository,
        file_path=file_path,
    )


def test_exact_and_normalized_duplicates_form_evidenced_cluster() -> None:
    result = build_task_clusters(
        [
            _item("r1", exact="x", normalized="n"),
            _item("r2", exact="x", normalized="n"),
            _item("r3", exact="y", normalized="n"),
        ]
    )

    cluster_ids = {assignment.cluster_id for assignment in result.assignments}
    assert len(cluster_ids) == 1
    assert {edge.evidence_type for edge in result.edges} == {
        "EXACT_PROMPT_DIGEST",
        "NORMALIZED_PROMPT_DIGEST",
    }


def test_source_task_identity_and_repository_file_coordinate_are_strong_evidence() -> None:
    result = build_task_clusters(
        [
            _item("r1", source="a", record_id="same"),
            _item("r2", source="a", record_id="same"),
            _item("r3", source="b", repository="org/repo", file_path="x.py"),
            _item("r4", source="c", repository="org/repo", file_path="x.py"),
        ]
    )

    by_key = {item.item_key: item.cluster_id for item in result.assignments}
    assert by_key["r1"] == by_key["r2"]
    assert by_key["r3"] == by_key["r4"]
    assert by_key["r1"] != by_key["r3"]


def test_ambiguous_near_duplicate_is_not_merged_or_counted_independent() -> None:
    result = build_task_clusters(
        [
            _item("r1", prompt="Implement a function to read a user supplied file safely."),
            _item("r2", prompt="Implement a function to read the user supplied file safely."),
            _item("r3", prompt="Compute the factorial of a number."),
        ]
    )

    by_key = {item.item_key: item for item in result.assignments}
    assert by_key["r1"].cluster_id != by_key["r2"].cluster_id
    assert by_key["r1"].independence_resolved is False
    assert by_key["r2"].independence_resolved is False
    assert by_key["r3"].independence_resolved is True
    assert result.unresolved_relations[0].evidence_type == "AMBIGUOUS_TEXT_SIMILARITY"


def test_cluster_ids_are_stable_under_input_reordering() -> None:
    items = [
        _item("r1", exact="x"),
        _item("r2", exact="x"),
        _item("r3", exact="z"),
    ]

    forward = {item.item_key: item.cluster_id for item in build_task_clusters(items).assignments}
    reverse = {
        item.item_key: item.cluster_id
        for item in build_task_clusters(list(reversed(items))).assignments
    }

    assert forward == reverse


def test_ambiguous_similarity_comparisons_are_bounded(
    monkeypatch,
) -> None:
    original = clustering_module.SequenceMatcher
    calls = 0

    def counting_matcher(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(clustering_module, "SequenceMatcher", counting_matcher)
    items = [
        _item(
            f"r{i + 1}",
            prompt=(
                "Implement a function that processes a user supplied value "
                f"for independent task {i:04d}."
            ),
        )
        for i in range(500)
    ]

    result = build_task_clusters(items)

    assert len(result.assignments) == 500
    assert calls <= 64 * 64

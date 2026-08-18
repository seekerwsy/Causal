"""Outcome-blind cross-source coverage audit for the five-CWE experiment."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime
import hashlib
import json
import os
import platform
import socket
import sys
from pathlib import Path
from typing import Any

from secaware.functional_audit.main_pool import MAIN_CWE_ORDER, PROFILE_BY_CWE, _sha


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(_canonical(value) + b"\n")


def _write_jsonl(path: Path, values: list[object]) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        for value in values:
            handle.write(_canonical(value).decode("utf-8") + "\n")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _environment() -> dict[str, object]:
    return {
        "captured_at_utc": datetime.now(UTC).isoformat(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version,
        "working_directory": os.getcwd(),
    }


def audit_cross_source_coverage(
    *,
    record_audit: Path,
    split_simulations: Path,
    config_path: Path,
    run_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    """Count non-baseline candidate clusters without model calls or generated outcomes."""

    if run_dir.exists():
        raise FileExistsError(run_dir)
    config = json.loads(config_path.read_text(encoding="utf-8"))
    main_cwes = tuple(config["main_cwes"])
    baseline_source = config["baseline_source"]
    candidate_sources = tuple(config["candidate_sources"])
    source_priority = tuple(config["source_priority"])
    if (
        config.get("schema_version") != "1.0"
        or not main_cwes
        or len(main_cwes) != len(set(main_cwes))
        or len(candidate_sources) != len(set(candidate_sources))
        or set(source_priority) != set(candidate_sources)
        or baseline_source in candidate_sources
    ):
        raise ValueError("cross-source coverage config is invalid")

    simulations = [
        row
        for row in _read_jsonl(split_simulations)
        if row.get("seed") == config["split_simulation_seed"]
        and row.get("discover_ratio") == config["split_discover_ratio"]
    ]
    if len(simulations) != 1:
        raise ValueError("cross-source split simulation is unavailable")
    split_by_cluster: dict[str, str] = {}
    for assignment in simulations[0]["assignments"]:
        cluster_id = assignment["cluster_id"]
        split = assignment["split"]
        previous = split_by_cluster.setdefault(cluster_id, split)
        if previous != split:
            raise ValueError("cross-source cluster has inconsistent split assignments")

    records = _read_jsonl(record_audit)
    baseline_rows = [
        row for row in records if row.get("coordinate", {}).get("source_id") == baseline_source
    ]
    baseline_clusters = {row["task_cluster_id"] for row in baseline_rows}
    baseline_exact = {row["exact_prompt_sha256"] for row in baseline_rows}

    source_order = {source: index for index, source in enumerate(source_priority)}
    candidates: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    excluded_overlap: list[dict[str, object]] = []
    filter_counts: Counter[str] = Counter()
    for row in records:
        source = row.get("coordinate", {}).get("source_id")
        if source not in candidate_sources:
            continue
        filter_counts["candidate_source_records"] += 1
        if row.get("language") != config["language"]:
            filter_counts["excluded_language"] += 1
            continue
        if row.get("neutrality") != config["neutrality"]:
            filter_counts["excluded_neutrality"] += 1
            continue
        matched_cwes = tuple(cwe for cwe in main_cwes if cwe in row.get("cwe_ids", ()))
        if not matched_cwes:
            filter_counts["excluded_cwe"] += 1
            continue
        overlap_reasons = tuple(
            reason
            for reason, overlaps in (
                ("baseline_task_cluster", row["task_cluster_id"] in baseline_clusters),
                ("baseline_exact_prompt", row["exact_prompt_sha256"] in baseline_exact),
            )
            if overlaps
        )
        if overlap_reasons:
            filter_counts["excluded_baseline_overlap"] += 1
            excluded_overlap.append(
                {
                    "schema_version": "1.0",
                    "source_id": source,
                    "record_id": row["coordinate"]["record_id"],
                    "task_cluster_id": row["task_cluster_id"],
                    "cwes": matched_cwes,
                    "reasons": overlap_reasons,
                }
            )
            continue
        filter_counts["candidate_records"] += 1
        for cwe in matched_cwes:
            candidates[(cwe, row["task_cluster_id"])].append(row)

    candidate_rows: list[dict[str, object]] = []
    source_counts: dict[str, dict[str, Counter[str]]] = {
        cwe: {source: Counter() for source in candidate_sources} for cwe in main_cwes
    }
    cwes_by_cluster: dict[str, set[str]] = defaultdict(set)
    for (cwe, cluster_id), members in sorted(
        candidates.items(), key=lambda item: (main_cwes.index(item[0][0]), item[0][1])
    ):
        ordered = sorted(
            members,
            key=lambda row: (
                source_order[row["coordinate"]["source_id"]],
                row["coordinate"]["record_id"],
            ),
        )
        representative = ordered[0]
        independence = (
            "strict"
            if all(row["cluster_independence_resolved"] for row in ordered)
            else "unresolved"
        )
        split = split_by_cluster.get(cluster_id)
        if split not in {"discover", "confirm", "UNRESOLVED"}:
            raise ValueError("cross-source candidate has no frozen split assignment")
        member_sources = sorted({row["coordinate"]["source_id"] for row in ordered})
        for source in member_sources:
            source_counts[cwe][source][independence] += 1
        cwes_by_cluster[cluster_id].add(cwe)
        candidate_rows.append(
            {
                "schema_version": "1.0",
                "cwe": cwe,
                "task_cluster_id": cluster_id,
                "independence": independence,
                "split": split,
                "representative": {
                    "source_id": representative["coordinate"]["source_id"],
                    "record_id": representative["coordinate"]["record_id"],
                    "exact_prompt_sha256": representative["exact_prompt_sha256"],
                    "prompt": representative["prompt"],
                },
                "members": [
                    {
                        "source_id": row["coordinate"]["source_id"],
                        "record_id": row["coordinate"]["record_id"],
                        "independence_resolved": row["cluster_independence_resolved"],
                    }
                    for row in ordered
                ],
            }
        )

    counts_by_cwe = {
        cwe: dict(Counter(row["independence"] for row in candidate_rows if row["cwe"] == cwe))
        for cwe in main_cwes
    }
    counts_by_cwe_split = {
        cwe: {
            independence: dict(
                Counter(
                    row["split"]
                    for row in candidate_rows
                    if row["cwe"] == cwe and row["independence"] == independence
                )
            )
            for independence in ("strict", "unresolved")
            if any(
                row["cwe"] == cwe and row["independence"] == independence for row in candidate_rows
            )
        }
        for cwe in main_cwes
    }
    source_counts_json = {
        cwe: {source: dict(counts) for source, counts in by_source.items() if sum(counts.values())}
        for cwe, by_source in source_counts.items()
    }
    cross_cwe_clusters = {
        cluster_id: sorted(cwes, key=main_cwes.index)
        for cluster_id, cwes in cwes_by_cluster.items()
        if len(cwes) > 1
    }

    run_dir.mkdir(parents=True, exist_ok=False)
    _write_jsonl(run_dir / "candidate-clusters.jsonl", candidate_rows)
    _write_jsonl(
        run_dir / "excluded-baseline-overlap.jsonl",
        sorted(
            excluded_overlap,
            key=lambda row: (row["source_id"], row["record_id"], row["task_cluster_id"]),
        ),
    )
    _write_json(run_dir / "config.json", config)
    _write_json(run_dir / "environment.json", _environment())
    _write_jsonl(
        run_dir / "commands.jsonl",
        [
            {
                "schema_version": "1.0",
                "argv": command_argv,
                "provider_calls": 0,
            }
        ],
    )
    report: dict[str, object] = {
        "schema_version": "1.0",
        "status": "CROSS_SOURCE_COVERAGE_AUDITED",
        "provider_calls": 0,
        "input_record_audit_sha256": _sha256(record_audit),
        "input_split_simulations_sha256": _sha256(split_simulations),
        "config_sha256": _sha256(config_path),
        "baseline_source": baseline_source,
        "filter_counts": dict(filter_counts),
        "candidate_clusters_by_cwe_independence": counts_by_cwe,
        "candidate_clusters_by_cwe_independence_split": counts_by_cwe_split,
        "source_membership_counts_by_cwe": source_counts_json,
        "cross_cwe_cluster_count": len(cross_cwe_clusters),
        "cross_cwe_clusters": cross_cwe_clusters,
    }
    _write_json(run_dir / "report.json", report)
    report["artifacts"] = {
        path.name: _sha256(path) for path in sorted(run_dir.iterdir()) if path.name != "report.json"
    }
    _write_json(run_dir / "report.json", report)
    return report


def prepare_cross_source_audit_packets(
    *,
    coverage_dir: Path,
    config_path: Path,
    run_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    """Convert strict, non-overlapping cross-source clusters into blind audit packets."""

    if run_dir.exists():
        raise FileExistsError(run_dir)
    config = json.loads(config_path.read_text(encoding="utf-8"))
    expected = config.get("expected_strict_clusters_by_cwe")
    if (
        config.get("schema_version") != "1.0"
        or type(expected) is not dict
        or set(expected) != set(MAIN_CWE_ORDER)
        or any(type(value) is not int or value < 1 for value in expected.values())
    ):
        raise ValueError("cross-source audit packet config is invalid")
    coverage_report = json.loads((coverage_dir / "report.json").read_text(encoding="utf-8"))
    candidates_path = coverage_dir / "candidate-clusters.jsonl"
    if _sha256(candidates_path) != coverage_report.get("artifacts", {}).get(
        "candidate-clusters.jsonl"
    ):
        raise ValueError("cross-source coverage candidate bundle does not match its report")

    selection_seed = int(config["selection_seed"])
    candidates = [
        row
        for row in _read_jsonl(candidates_path)
        if row["independence"] == "strict" and row["split"] in {"discover", "confirm"}
    ]
    actual = Counter(row["cwe"] for row in candidates)
    if actual != Counter(expected):
        raise ValueError(f"strict cross-source count mismatch: {dict(actual)}")
    clusters = [row["task_cluster_id"] for row in candidates]
    if len(clusters) != len(set(clusters)):
        raise ValueError("cross-source audit packet has a cross-CWE cluster collision")

    packets: list[dict[str, object]] = []
    for row in candidates:
        cwe = row["cwe"]
        representative = row["representative"]
        source_id = representative["source_id"]
        source_record_id = str(representative["record_id"])
        audit_record_id = f"{source_id}:{source_record_id}"
        rank_key = hashlib.sha256(
            (
                f"{selection_seed}|{cwe}|{row['split']}|{row['task_cluster_id']}|"
                f"{representative['exact_prompt_sha256']}"
            ).encode()
        ).hexdigest()
        content = {
            "schema_version": "1.0",
            "audit_protocol": "five-cwe-cross-source-outcome-blind-v1",
            "record_id": audit_record_id,
            "source_record_id": source_record_id,
            "task_cluster_id": row["task_cluster_id"],
            "source_id": source_id,
            "source_prompt_sha256": representative["exact_prompt_sha256"],
            "language": "python",
            "cwe": cwe,
            "source_cwe_ids": (cwe,),
            "split": row["split"],
            "task_family": PROFILE_BY_CWE[cwe]["task_family"],
            "oracle_profile_id": PROFILE_BY_CWE[cwe]["oracle_profile_id"],
            "finite_profile_scope": PROFILE_BY_CWE[cwe]["scope"],
            "prompt": representative["prompt"],
            "rank_key": rank_key,
            "blindness": {
                "generated_code_withheld": True,
                "intervention_arm_withheld": True,
                "model_identity_withheld": True,
                "oracle_label_withheld": True,
                "outcomes_withheld": True,
            },
        }
        packets.append({**content, "packet_id": "main_pool_audit_packet_" + _sha(content)})
    packets.sort(
        key=lambda item: (MAIN_CWE_ORDER.index(item["cwe"]), item["split"], item["rank_key"])
    )
    ranks: Counter[tuple[str, str]] = Counter()
    ranked_packets: list[dict[str, object]] = []
    for packet in packets:
        key = (packet["cwe"], packet["split"])
        ranks[key] += 1
        ranked_packets.append({**packet, "rank_within_cwe_split": ranks[key]})

    run_dir.mkdir(parents=True, exist_ok=False)
    _write_jsonl(run_dir / "candidate-packets.jsonl", ranked_packets)
    _write_json(run_dir / "config.json", config)
    _write_json(run_dir / "environment.json", _environment())
    _write_jsonl(
        run_dir / "commands.jsonl",
        [{"schema_version": "1.0", "argv": command_argv, "provider_calls": 0}],
    )
    report: dict[str, object] = {
        "schema_version": "1.0",
        "status": "CROSS_SOURCE_AUDIT_PACKETS_READY",
        "counts": {
            "packets": len(ranked_packets),
            "provider_calls": 0,
            "completed": 0,
            "errors": 0,
            "pending": len(ranked_packets),
        },
        "candidates_by_cwe_split": {
            cwe: {split: ranks[(cwe, split)] for split in ("discover", "confirm")}
            for cwe in MAIN_CWE_ORDER
        },
        "coverage_report_sha256": _sha256(coverage_dir / "report.json"),
        "candidate_bundle_sha256": _sha256(candidates_path),
        "config_sha256": _sha256(config_path),
        "packet_bundle_sha256": _sha256(run_dir / "candidate-packets.jsonl"),
    }
    _write_json(run_dir / "report.json", report)
    return report


__all__ = ["audit_cross_source_coverage", "prepare_cross_source_audit_packets"]

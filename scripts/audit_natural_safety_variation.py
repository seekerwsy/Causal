"""Audit natural prompt-side safety-feature variation in deduplicated legacy sources."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
import platform
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secaware.config import TSGConfig
from secaware.extractors.factory import extraction_policy, extractor_for_config
from secaware.io.jsonl import write_jsonl
from secaware.schema.experiments import PromptRole
from secaware.schema.features import PromptExtractorBackend
from secaware.schema.records import PromptRecord
from secaware.tsg.builder import build_prompt_tsg
from secaware.tsg.graph import record_to_multidigraph
from secaware.tsg.motifs import motif_query_vector
from secaware.tsg.queries import feature_state_vector


_TARGETS = {
    "CWE-20": {
        "task": "task.input_consumption",
        "safety": "safety.input_validation",
        "motif": "untrusted_source_to_sensitive_sink_without_guard",
        "task_family": "input_handling",
    },
    "CWE-22": {
        "task": "task.file_read",
        "safety": "safety.path_normalization",
        "motif": "user_path_to_file_open_without_guard",
        "task_family": "file_access",
    },
    "CWE-502": {
        "task": "task.object_deserialization",
        "safety": "safety.safe_deserialization",
        "motif": "untrusted_data_to_deserialization_sink",
        "task_family": "deserialization",
    },
    "CWE-78": {
        "task": "task.process_launch",
        "safety": "safety.safe_subprocess",
        "motif": "user_input_to_shell_without_guard",
        "task_family": "command_execution",
    },
    "CWE-89": {
        "task": "task.database_query",
        "safety": "safety.sql_parameterization",
        "motif": "user_string_to_sql_without_parameterization",
        "task_family": "sql_query",
    },
}


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(_canonical(value) + b"\n")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _select(
    rows: list[dict[str, Any]],
    config: dict[str, Any],
) -> tuple[list[tuple[dict[str, Any], str]], list[dict[str, object]]]:
    target_cwes = set(config["target_cwes"])
    priority = {source: index for index, source in enumerate(config["source_priority"])}
    excluded_sources = set(config["excluded_sources"])
    candidates: dict[str, list[tuple[dict[str, Any], str]]] = defaultdict(list)
    exclusions: list[dict[str, object]] = []
    for item in rows:
        source = item["coordinate"]["source_id"]
        memberships = sorted(target_cwes.intersection(item["cwe_ids"]))
        reason = None
        if source in excluded_sources:
            reason = "excluded_exact_duplicate_source"
        elif source not in priority or not memberships:
            continue
        elif item["language"] != config["language"]:
            reason = "language_mismatch"
        elif item["neutrality"] != config["neutrality"]:
            reason = "neutrality_mismatch"
        elif item["cluster_independence_resolved"] is not True:
            reason = "independence_unresolved"
        elif len(memberships) != 1:
            reason = "ambiguous_target_cwe"
        if reason is not None:
            exclusions.append(
                {
                    "source_id": source,
                    "record_id": str(item["coordinate"]["record_id"]),
                    "task_cluster_id": item["task_cluster_id"],
                    "reason": reason,
                    "target_cwes": memberships,
                }
            )
            continue
        candidates[item["task_cluster_id"]].append((item, memberships[0]))

    selected: list[tuple[dict[str, Any], str]] = []
    for cluster_id, members in sorted(candidates.items()):
        members.sort(
            key=lambda value: (
                priority[value[0]["coordinate"]["source_id"]],
                str(value[0]["coordinate"]["record_id"]),
            )
        )
        selected.append(members[0])
        for duplicate, cwe in members[1:]:
            exclusions.append(
                {
                    "source_id": duplicate["coordinate"]["source_id"],
                    "record_id": str(duplicate["coordinate"]["record_id"]),
                    "task_cluster_id": cluster_id,
                    "reason": "duplicate_task_cluster",
                    "target_cwes": [cwe],
                }
            )
    selected.sort(
        key=lambda value: (
            value[1],
            priority[value[0]["coordinate"]["source_id"]],
            str(value[0]["coordinate"]["record_id"]),
        )
    )
    exclusions.sort(
        key=lambda item: (str(item["reason"]), str(item["source_id"]), str(item["record_id"]))
    )
    return selected, exclusions


def audit(
    *,
    record_audit_path: Path,
    config_path: Path,
    output_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    if output_dir.exists():
        raise FileExistsError(output_dir)
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if (
        config.get("schema_version") != "1.0"
        or not config.get("target_cwes")
        or not set(config["target_cwes"]) <= set(_TARGETS)
    ):
        raise ValueError("natural safety variation config failed validation")
    selected, exclusions = _select(_read_jsonl(record_audit_path), config)
    if not selected:
        raise ValueError("natural safety variation selected no prompts")

    tsg_config = TSGConfig(
        prompt_extractor=PromptExtractorBackend.DETERMINISTIC_CATALOG_V1
    )
    policy = extraction_policy(tsg_config)
    extractor = extractor_for_config(tsg_config)
    prompts: list[PromptRecord] = []
    proposals = []
    graphs = []
    feature_rows: list[dict[str, object]] = []
    candidate_phrases: list[dict[str, object]] = []
    for item, cwe in selected:
        source_id = item["coordinate"]["source_id"]
        record_id = str(item["coordinate"]["record_id"])
        prompt = PromptRecord(
            prompt_id=f"natural-{source_id}-{record_id}",
            task_id=item["task_cluster_id"],
            split="discover",
            language="python",
            task_family=_TARGETS[cwe]["task_family"],
            cwe=cwe,
            prompt=item["prompt"],
            prompt_role=PromptRole.NEUTRAL_BASELINE,
            counterpart_prompt_id=None,
            oracle_profile_id=config["oracle_profiles"][cwe],
        )
        proposal = extractor.extract(prompt, policy)
        graph_record = build_prompt_tsg(proposal, prompt)
        graph = record_to_multidigraph(graph_record)
        features = {
            feature_id: state.value for feature_id, state in feature_state_vector(graph)
        }
        motifs = {
            motif.value: present for motif, present in motif_query_vector(graph)
        }
        targets = _TARGETS[cwe]
        feature_rows.append(
            {
                "prompt_id": prompt.prompt_id,
                "task_cluster_id": prompt.task_id,
                "source_id": source_id,
                "source_record_id": record_id,
                "cwe": cwe,
                "task_feature_id": targets["task"],
                "task_state": features[targets["task"]],
                "safety_feature_id": targets["safety"],
                "safety_state": features[targets["safety"]],
                "motif_id": targets["motif"],
                "motif_state": "present" if motifs[targets["motif"]] else "absent",
            }
        )
        text = prompt.prompt.casefold()
        hits = [phrase for phrase in config["candidate_phrase_families"][cwe] if phrase in text]
        if hits:
            candidate_phrases.append(
                {
                    "prompt_id": prompt.prompt_id,
                    "task_cluster_id": prompt.task_id,
                    "source_id": source_id,
                    "source_record_id": record_id,
                    "cwe": cwe,
                    "phrase_hits": hits,
                    "prompt": prompt.prompt,
                    "diagnostic_only": True,
                }
            )
        prompts.append(prompt)
        proposals.append(proposal)
        graphs.append(graph_record)

    distributions: list[dict[str, object]] = []
    for cwe in config["target_cwes"]:
        scope = [item for item in feature_rows if item["cwe"] == cwe]
        for kind in ("task", "safety", "motif"):
            counts = Counter(str(item[f"{kind}_state"]) for item in scope)
            distributions.append(
                {
                    "cwe": cwe,
                    "variable_kind": kind,
                    "task_count": len(scope),
                    "state_counts": dict(sorted(counts.items())),
                    "varying": len(counts) > 1,
                }
            )

    output_dir.mkdir(parents=True, exist_ok=False)
    write_jsonl(output_dir / "selected-prompts.jsonl", prompts)
    write_jsonl(output_dir / "prompt-extraction-proposals.jsonl", proposals)
    write_jsonl(output_dir / "prompt-tsg.jsonl", graphs)
    write_jsonl(output_dir / "feature-rows.jsonl", feature_rows)
    write_jsonl(output_dir / "feature-distributions.jsonl", distributions)
    write_jsonl(output_dir / "candidate-phrase-prompts.jsonl", candidate_phrases)
    write_jsonl(output_dir / "selection-exclusions.jsonl", exclusions)
    _write_json(output_dir / "command.json", {"argv": list(command_argv)})
    _write_json(output_dir / "config.json", config)
    _write_json(
        output_dir / "environment.json",
        {
            "captured_at_utc": datetime.now(UTC).isoformat(),
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "python": sys.version,
            "python_executable": sys.executable,
            "working_directory": os.getcwd(),
        },
    )
    safety_varying = any(
        item["variable_kind"] == "safety" and item["varying"] for item in distributions
    )
    report: dict[str, object] = {
        "schema_version": "1.0",
        "audit_id": config["audit_id"],
        "status": "NATURAL_VARIATION_FOUND" if safety_varying else "NO_NATURAL_VARIATION_FOUND",
        "counts": {
            "selected_independent_tasks": len(prompts),
            "by_cwe": dict(sorted(Counter(item.cwe for item in prompts).items())),
            "by_source": dict(sorted(Counter(item.prompt_id.split("-", 2)[1] for item in prompts).items())),
            "candidate_phrase_prompts": len(candidate_phrases),
            "exclusions": len(exclusions),
            "completed": len(prompts),
            "failed": 0,
            "running": 0,
            "pending": 0,
        },
        "decision": {
            "deterministic_safety_variation": safety_varying,
            "candidate_phrase_review_required": bool(candidate_phrases),
            "llm_scale_up_approved": False,
            "reason": (
                "LLM scale-up requires manual review of every broad safety-phrase candidate "
                "and evidence that at least one candidate expresses the scoped mechanism."
            ),
        },
        "inputs": {
            "record_audit_sha256": hashlib.sha256(record_audit_path.read_bytes()).hexdigest(),
            "config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
        },
        "extractor_policy_sha256": policy.policy_sha256,
    }
    _write_json(output_dir / "report.json", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record-audit", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = audit(
        record_audit_path=args.record_audit,
        config_path=args.config,
        output_dir=args.output_dir,
        command_argv=tuple(sys.argv),
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()

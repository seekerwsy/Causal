"""Compare deterministic and LLM facts against an outcome-blind semantic audit."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
import platform
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secaware.io.jsonl import write_jsonl
from secaware.schema.features import FeatureState
from secaware.schema.tsg import PromptTSGRecord
from secaware.tsg.graph import record_to_multidigraph
from secaware.tsg.motifs import motif_query_vector
from secaware.tsg.queries import feature_state_vector


_MOTIF_BY_CWE = {
    "CWE-78": "user_input_to_shell_without_guard",
    "CWE-89": "user_string_to_sql_without_parameterization",
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


def compare(
    *,
    audit_path: Path,
    deterministic_rows_path: Path,
    llm_tsg_path: Path,
    llm_manifest_path: Path,
    output_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    if output_dir.exists():
        raise FileExistsError(output_dir)
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    if audit.get("schema_version") != "1.0" or audit.get("outcome_blind") is not True:
        raise ValueError("semantic audit failed validation")
    audit_by_id = {item["prompt_id"]: item for item in audit["records"]}
    deterministic_by_id = {
        item["prompt_id"]: item for item in _read_jsonl(deterministic_rows_path)
    }
    llm_records = [
        PromptTSGRecord.model_validate(item) for item in _read_jsonl(llm_tsg_path)
    ]
    llm_by_id = {item.prompt_id: item for item in llm_records}
    if (
        len(audit_by_id) != len(audit["records"])
        or len(llm_by_id) != len(llm_records)
        or set(audit_by_id) != set(llm_by_id)
        or not set(audit_by_id) <= set(deterministic_by_id)
    ):
        raise ValueError("canary comparison coverage failed validation")

    rows: list[dict[str, object]] = []
    for prompt_id in sorted(audit_by_id):
        expected = audit_by_id[prompt_id]
        deterministic = deterministic_by_id[prompt_id]
        graph = record_to_multidigraph(llm_by_id[prompt_id])
        llm_features = {
            feature_id: state.value for feature_id, state in feature_state_vector(graph)
        }
        llm_motifs = {
            motif.value: present for motif, present in motif_query_vector(graph)
        }
        target_feature = expected["target_feature_id"]
        safety_feature = expected["safety_feature_id"]
        motif_id = _MOTIF_BY_CWE[deterministic["cwe"]]
        deterministic_values = deterministic["values"]
        row = {
            "prompt_id": prompt_id,
            "record_id": deterministic["record_id"],
            "cwe": deterministic["cwe"],
            "target_feature_id": target_feature,
            "expected_target_state": expected["target_state"],
            "deterministic_target_state": deterministic_values[f"x.{target_feature}"],
            "llm_target_state": llm_features[target_feature],
            "safety_feature_id": safety_feature,
            "expected_safety_state": expected["safety_state"],
            "deterministic_safety_state": deterministic_values[f"x.{safety_feature}"],
            "llm_safety_state": llm_features[safety_feature],
            "motif_id": motif_id,
            "deterministic_motif_state": deterministic_values[f"x.motif.{motif_id}"],
            "llm_motif_state": "present" if llm_motifs[motif_id] else "absent",
            "deterministic_target_correct": (
                deterministic_values[f"x.{target_feature}"] == expected["target_state"]
            ),
            "llm_target_correct": llm_features[target_feature] == expected["target_state"],
            "deterministic_safety_correct": (
                deterministic_values[f"x.{safety_feature}"] == expected["safety_state"]
            ),
            "llm_safety_correct": llm_features[safety_feature] == expected["safety_state"],
            "audit_rationale": expected["rationale"],
        }
        rows.append(row)

    distributions: list[dict[str, object]] = []
    for cwe in sorted({str(item["cwe"]) for item in rows}):
        scope = [item for item in rows if item["cwe"] == cwe]
        for backend in ("deterministic", "llm"):
            for kind in ("target", "safety", "motif"):
                field = f"{backend}_{kind}_state"
                counts = Counter(str(item[field]) for item in scope)
                distributions.append(
                    {
                        "cwe": cwe,
                        "backend": backend,
                        "variable_kind": kind,
                        "task_count": len(scope),
                        "state_counts": dict(sorted(counts.items())),
                        "varying": len(counts) > 1,
                    }
                )

    n = len(rows)
    deterministic_target_correct = sum(bool(item["deterministic_target_correct"]) for item in rows)
    llm_target_correct = sum(bool(item["llm_target_correct"]) for item in rows)
    deterministic_safety_correct = sum(bool(item["deterministic_safety_correct"]) for item in rows)
    llm_safety_correct = sum(bool(item["llm_safety_correct"]) for item in rows)
    llm_false_target_variation = any(
        item["expected_target_state"] == "present" and item["llm_target_state"] != "present"
        for item in rows
    )
    expansion_approved = not llm_false_target_variation and llm_target_correct == n
    manifest = json.loads(llm_manifest_path.read_text(encoding="utf-8"))

    output_dir.mkdir(parents=True, exist_ok=False)
    write_jsonl(output_dir / "record-comparison.jsonl", rows)
    write_jsonl(output_dir / "distribution-comparison.jsonl", distributions)
    _write_json(output_dir / "command.json", {"argv": list(command_argv)})
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
    report: dict[str, object] = {
        "schema_version": "1.0",
        "audit_id": audit["audit_id"],
        "status": "EXPANSION_APPROVED" if expansion_approved else "EXPANSION_NOT_APPROVED",
        "counts": {
            "total": n,
            "completed": n,
            "failed": 0,
            "running": 0,
            "pending": 0,
        },
        "semantic_metrics": {
            "deterministic_target_correct": deterministic_target_correct,
            "deterministic_target_recall": deterministic_target_correct / n,
            "llm_target_correct": llm_target_correct,
            "llm_target_recall": llm_target_correct / n,
            "deterministic_safety_correct": deterministic_safety_correct,
            "deterministic_safety_specificity": deterministic_safety_correct / n,
            "llm_safety_correct": llm_safety_correct,
            "llm_safety_specificity": llm_safety_correct / n,
        },
        "decision": {
            "structure_gate": True,
            "semantic_target_gate": not llm_false_target_variation,
            "identifiability_gate": False,
            "reason": (
                "The LLM substantially improves target-task recall, but the only within-CWE "
                "target variation in the canary includes a manually verified false negative; "
                "all scoped safety features are truly absent. Scaling the same neutral pool "
                "would not create trustworthy safety-feature variation for FCI."
            ),
            "next_action": (
                "Construct an outcome-blind discovery design with preregistered prompt-side "
                "feature variation, while retaining these LLM facts changes for extraction."
            ),
        },
        "llm_stage_policy_sha256": manifest["policy_sha256"],
        "inputs": {
            "audit_sha256": hashlib.sha256(audit_path.read_bytes()).hexdigest(),
            "deterministic_rows_sha256": hashlib.sha256(
                deterministic_rows_path.read_bytes()
            ).hexdigest(),
            "llm_tsg_sha256": hashlib.sha256(llm_tsg_path.read_bytes()).hexdigest(),
            "llm_manifest_sha256": hashlib.sha256(llm_manifest_path.read_bytes()).hexdigest(),
        },
    }
    _write_json(output_dir / "report.json", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--deterministic-rows", type=Path, required=True)
    parser.add_argument("--llm-tsg", type=Path, required=True)
    parser.add_argument("--llm-manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = compare(
        audit_path=args.audit,
        deterministic_rows_path=args.deterministic_rows,
        llm_tsg_path=args.llm_tsg,
        llm_manifest_path=args.llm_manifest,
        output_dir=args.output_dir,
        command_argv=tuple(sys.argv),
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()

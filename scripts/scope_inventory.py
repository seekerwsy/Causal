"""Recount the outcome-blind Python source scope in the frozen v4 pool."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

from prompt_mechanism_study.artifact_io import verify_bundle


ROOT = Path(__file__).resolve().parents[1]
POOL = ROOT / "data/dataset-curation/research-candidate-pool-v4"
CWES = ("CWE-78", "CWE-502", "CWE-89", "CWE-22")


def main() -> None:
    verify_bundle(POOL)
    tasks = json.loads((POOL / "tasks.json").read_text(encoding="utf-8"))
    screens = json.loads((POOL / "candidate-screens.json").read_text(encoding="utf-8"))
    python_tasks = {row["task_unit_id"]: row for row in tasks if row["language"] == "python"}
    atomic_by_task: dict[str, list[dict]] = defaultdict(list)
    for row in screens:
        if row["candidate_family"] == "Atomic" and row["task_unit_id"] in python_tasks:
            atomic_by_task[row["task_unit_id"]].append(row)

    output = {
        "pool_status": json.loads((POOL / "report.json").read_text(encoding="utf-8"))["status"],
        "task_units": len(tasks),
        "python_task_units": len(python_tasks),
        "cwe_labels_are_source_metadata": True,
        "formal_admissions": sum(row["formal_admission"] for row in screens),
        "cwes": [],
    }
    for cwe in CWES:
        group = {
            key: row for key, row in python_tasks.items()
            if cwe in row["source_declared_cwe_ids"]
        }
        reviewed = {key for key in group if atomic_by_task[key]}
        supported = [
            row for key in group for row in atomic_by_task[key]
            if row["status"] == "SOURCE_SUPPORTED_PENDING_INTERVENTION"
        ]
        features = Counter(
            row["candidate_policy"]["factor"]["actionable_feature_id"]
            for row in supported
        )
        output["cwes"].append({
            "source_label": cwe,
            "python_task_units": len(group),
            "task_units_with_prior_atomic_screen": len(reviewed),
            "task_units_with_prior_source_supported_screen": len({
                row["task_unit_id"] for row in supported
            }),
            "source_supported_task_policy_rows": len(supported),
            "supported_rows_by_feature": dict(sorted(features.items())),
            "formal_admissions": sum(row["formal_admission"] for key in group
                                     for row in atomic_by_task[key]),
        })
    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

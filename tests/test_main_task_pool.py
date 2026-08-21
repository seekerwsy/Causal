from __future__ import annotations

import hashlib
import json
from pathlib import Path

from secaware.functional_audit.main_pool import MAIN_CWE_ORDER
from secaware.functional_audit.main_task_pool import freeze_main_task_pool


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, separators=(",", ":")) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, values: list[object]) -> None:
    path.write_text(
        "".join(json.dumps(value, separators=(",", ":")) + "\n" for value in values),
        encoding="utf-8",
    )


def _audited_pool(tmp_path: Path, name: str, split: str) -> tuple[Path, Path]:
    prepared = tmp_path / f"{name}-prepared"
    reconciled = tmp_path / f"{name}-reconciled"
    prepared.mkdir()
    reconciled.mkdir()
    packets: list[dict[str, object]] = []
    decisions: list[dict[str, object]] = []
    for index, cwe in enumerate(MAIN_CWE_ORDER):
        packet_id = f"packet-{name}-{index}"
        cluster_id = f"cluster-{name}-{index}"
        packet = {
            "packet_id": packet_id,
            "record_id": f"record-{name}-{index}",
            "task_cluster_id": cluster_id,
            "source_id": name,
            "source_prompt_sha256": f"digest-{name}-{index}",
            "prompt": f"Write a Python function for {cwe}.",
            "language": "python",
            "cwe": cwe,
            "split": split,
            "task_family": "task-family",
            "oracle_profile_id": f"profile-{cwe}",
            "blindness": {
                "generated_code_withheld": True,
                "intervention_arm_withheld": True,
                "model_identity_withheld": True,
                "oracle_label_withheld": True,
                "outcomes_withheld": True,
            },
        }
        packets.append(packet)
        decisions.append(
            {
                "packet_id": packet_id,
                "task_cluster_id": cluster_id,
                "decision_id": f"decision-{name}-{index}",
                "adjudication": "retained_response_revalidated",
                "response_sha256": f"response-{name}-{index}",
                "override_sha256": None,
                "audit": {
                    "eligible": True,
                    "judgeability": "semantic_only",
                    "requirements": [
                        {
                            "requirement_id": "req_task",
                            "kind": "behavior",
                            "criterion": "Implement the task.",
                            "prompt_evidence_quote": f"Write a Python function for {cwe}.",
                        }
                    ],
                    "environment_dependencies": [],
                },
            }
        )
    packet_path = prepared / "candidate-packets.jsonl"
    decision_path = reconciled / "decisions.jsonl"
    _write_jsonl(packet_path, packets)
    _write_json(
        prepared / "report.json",
        {"packet_bundle_sha256": hashlib.sha256(packet_path.read_bytes()).hexdigest()},
    )
    _write_jsonl(decision_path, decisions)
    _write_json(
        reconciled / "report.json",
        {"artifacts": {"decisions.jsonl": hashlib.sha256(decision_path.read_bytes()).hexdigest()}},
    )
    return prepared, reconciled


def test_freeze_main_task_pool_preserves_splits_and_exposes_scope_gaps(tmp_path: Path) -> None:
    baseline_prepared, baseline_reconciled = _audited_pool(tmp_path, "baseline", "discover")
    supplement_prepared, supplement_reconciled = _audited_pool(tmp_path, "supplement", "confirm")
    config = tmp_path / "config.json"
    _write_json(
        config,
        {
            "schema_version": "1.0",
            "expected_eligible_by_cwe_split": {
                cwe: {"discover": 1, "confirm": 1} for cwe in MAIN_CWE_ORDER
            },
            "paper_min_independent_tasks": 2,
        },
    )

    report = freeze_main_task_pool(
        baseline_prepared_dir=baseline_prepared,
        baseline_reconciled_dir=baseline_reconciled,
        supplement_prepared_dir=supplement_prepared,
        supplement_reconciled_dir=supplement_reconciled,
        config_path=config,
        run_dir=tmp_path / "frozen",
        command_argv=("freeze",),
    )

    assert report["counts"] == {
        "tasks": 10,
        "provider_calls": 0,
        "generated_code": 0,
        "outcomes_observed": 0,
    }
    assert report["aggregate_by_split"] == {"discover": 5, "confirm": 5}
    assert report["aggregate_scope_feasibility"]["discover"] == {
        "independent_tasks": 5,
        "meets_paper_minimum": True,
        "requires_separately_approved_estimand": True,
    }
    assert all(
        not report["per_cwe_scope_feasibility"][cwe]["discover"]["meets_paper_minimum"]
        for cwe in MAIN_CWE_ORDER
    )

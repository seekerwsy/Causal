from __future__ import annotations

import hashlib
import json
from pathlib import Path

from secaware.exploratory.independent_validation_pool import (
    audit_independent_validation_pool,
)


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, separators=(",", ":")) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, values: list[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(value, separators=(",", ":")) + "\n" for value in values),
        encoding="utf-8",
    )


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_independent_validation_pool_rejects_overlap_and_unsafe_candidates(
    tmp_path: Path,
) -> None:
    selection = tmp_path / "selection.json"
    _write_json(
        selection,
        {
            "tasks": [
                {"task_cluster_id": f"used-{index}"}
                for index in range(93)
            ]
        },
    )
    hypothesis = tmp_path / "hypothesis.jsonl"
    hypothesis_id = "hypothesis_" + "a" * 64
    _write_jsonl(
        hypothesis,
        [
            {
                "hypothesis_id": hypothesis_id,
                "model_id": "phi-4-14b",
                "source_variable_id": "z.target_mechanism_realized",
                "target_variable_id": "y.discovery_functional",
            }
        ],
    )
    candidates = tmp_path / "candidates.jsonl"
    candidate_rows = []
    decision_rows = []
    for index in range(59):
        cluster = "used-0" if index == 0 else f"candidate-{index}"
        cwe = ("CWE-78", "CWE-89", "CWE-502", "CWE-328", "CWE-338")[index % 5]
        candidate_rows.append(
            {
                "independence": "strict",
                "task_cluster_id": cluster,
                "cwe": cwe,
                "split": "confirm",
                "representative": {
                    "source_id": "source-a",
                    "record_id": f"record-{index}",
                    "exact_prompt_sha256": f"digest-{index}",
                },
            }
        )
        accepted = index < 52
        decision_rows.append(
            {
                "task_cluster_id": cluster,
                "audit": {
                    "eligible": accepted,
                    "reason_code": "accepted" if accepted else "outside_profile",
                    "rationale": "fixture",
                },
            }
        )
    _write_jsonl(candidates, candidate_rows)
    decisions = tmp_path / "decisions.jsonl"
    _write_jsonl(decisions, decision_rows)
    config = tmp_path / "config.json"
    _write_json(
        config,
        {
            "schema_version": "1.0",
            "audit_id": "five_cwe_independent_validation_pool_preflight_v1",
            "frozen_hypothesis": {
                "hypothesis_id": hypothesis_id,
                "model_id": "phi-4-14b",
                "source_variable_id": "z.target_mechanism_realized",
                "target_variable_id": "y.discovery_functional",
                "minimum_bootstrap_support": 0.8,
            },
            "inputs": {
                name: {"path": path.relative_to(tmp_path).as_posix(), "sha256": _sha(path)}
                for name, path in {
                    "method_development_selection": selection,
                    "cross_source_candidates": candidates,
                    "cross_source_decisions": decisions,
                    "frozen_hypotheses": hypothesis,
                }.items()
            },
            "eligibility_policy": {
                "independence": "strict",
                "disjoint_from_method_development": True,
                "accepted_reason_code": "accepted",
                "forbidden_reason_codes": [
                    "no_target_operation",
                    "outside_profile",
                    "weak_mechanism_required",
                ],
                "minimum_validation_tasks": 50,
                "required_cwes": ["CWE-78", "CWE-89", "CWE-502", "CWE-328", "CWE-338"],
                "safety_neutrality_required": True,
            },
            "provider_calls_allowed": False,
            "outcomes_allowed": False,
        },
    )

    report = audit_independent_validation_pool(
        repo_root=tmp_path,
        config_path=config,
        run_dir=tmp_path / "run",
        command_argv=("audit",),
    )

    assert report["status"] == "INDEPENDENT_VALIDATION_POOL_READY"
    assert report["counts"]["overlap_exclusions"] == 1
    assert report["counts"]["independent_eligible"] == 51
    assert report["counts"]["independent_ineligible"] == 7
    assert report["provider_calls"] == 0
    assert (tmp_path / "run" / "artifact-manifest.json").is_file()

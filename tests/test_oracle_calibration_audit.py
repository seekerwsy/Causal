from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from secaware.oracle.calibration_audit import build_oracle_calibration_evidence_audit


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, separators=(",", ":")) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, values: list[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(value, separators=(",", ":")) + "\n" for value in values),
        encoding="utf-8",
    )


def _fixture(root: Path) -> tuple[dict[str, object], Path, Path, Path]:
    prompt = "Use a fixed operation name and execute it without a shell."
    prompt_sha256 = hashlib.sha256(prompt.encode()).hexdigest()
    contract = root / "coverage-contract.json"
    packets = root / "packets.jsonl"
    decisions = root / "scope-decisions.jsonl"
    _write_json(
        contract,
        {
            "schema_version": "1.0",
            "contract_name": "test-contract",
            "profiles": [
                {
                    "schema_version": "1.0",
                    "profile_id": "python.cwe78.closed_mapping_subprocess.v1",
                    "cwe": "CWE-78",
                    "task_families": ["command_execution"],
                    "zero_finding_supported": False,
                    "analyzer_rule_ids": ["B603"],
                    "calibration_fixture_ids": [],
                }
            ],
        },
    )
    _write_jsonl(
        packets,
        [
            {
                "packet_id": "packet-a",
                "source_prompt_id": "prompt-a",
                "source_prompt_sha256": prompt_sha256,
                "cwe_scope": "CWE-78",
                "language": "python",
                "prompt": prompt,
            }
        ],
    )
    _write_jsonl(
        decisions,
        [
            {
                "schema_version": "1.0",
                "source_prompt_id": "prompt-a",
                "source_prompt_sha256": prompt_sha256,
                "packet_id": "packet-a",
                "cwe": "CWE-78",
                "candidate_profile_id": "python.cwe78.closed_mapping_subprocess.v1",
                "decision": "PROFILE_MATCH",
                "evidence_quote": "fixed operation name",
                "rationale": "The task has a finite command vocabulary.",
                "adjudicator_kind": "CODEX",
            }
        ],
    )
    _write_jsonl(
        root / "data" / "source.jsonl",
        [
            {
                "prompt_id": "source-1",
                "cwe_identifier": "CWE-78",
                "origin_code": "import os\nos.system(input())\n",
                "language": "python",
            }
        ],
    )
    _write_jsonl(
        root / "data" / "errors.jsonl",
        [
            {
                "schema_version": "1.0",
                "event_id": "error-1",
                "event": "example",
                "cause": "example",
                "impact": "none",
                "recovery": "fixed",
            }
        ],
    )
    config: dict[str, object] = {
        "schema_version": "1.0",
        "audit_name": "test-audit",
        "selected_cwes": ["CWE-78"],
        "operator_error_ledger_path": "data/errors.jsonl",
        "dataset_sources": [
            {
                "source_id": "source_a",
                "path": "data/source.jsonl",
                "record_id_field": "prompt_id",
                "cwe_field": "cwe_identifier",
                "cwe_value_pattern": "^(?P<cwe>CWE-[1-9][0-9]{0,5})$",
                "code_field": "origin_code",
                "language_field": "language",
                "label_provenance": "SAME_STATIC_ANALYZER",
                "expected_security_label": "INSECURE",
            }
        ],
    }
    return config, contract, packets, decisions


def test_calibration_audit_preserves_contract_and_never_overwrites(tmp_path: Path) -> None:
    config, contract, packets, decisions = _fixture(tmp_path)
    before = contract.read_bytes()
    run_dir = tmp_path / "run"

    report = build_oracle_calibration_evidence_audit(
        project_root=tmp_path,
        config=config,
        coverage_contract_path=contract,
        pilot_packets_path=packets,
        scope_decisions_path=decisions,
        run_dir=run_dir,
        command_argv=("secaware", "audit-oracle-calibration"),
    )

    assert report["status"] == "CALIBRATION_EVIDENCE_INSUFFICIENT"
    assert report["counts"] == {
        "selected_cwes": 1,
        "coverage_profiles": 1,
        "scope_decisions": 1,
        "profile_matches": 1,
        "profile_scope_mismatches": 0,
        "dataset_code_candidates": 1,
        "directly_admissible_fixtures": 0,
        "profiles_admitted": 0,
    }
    assert contract.read_bytes() == before
    candidate = json.loads((run_dir / "candidates.jsonl").read_text(encoding="utf-8"))
    assert candidate["eligibility"] == "CANDIDATE_ONLY"
    assert candidate["candidate_profile_ids"] == ["python.cwe78.closed_mapping_subprocess.v1"]
    assert "LABEL_DEPENDS_ON_STATIC_ANALYZER" in candidate["blocking_reasons"]
    assert json.loads((run_dir / "errors.json").read_text(encoding="utf-8"))["errors"] == []
    with pytest.raises(FileExistsError):
        build_oracle_calibration_evidence_audit(
            project_root=tmp_path,
            config=config,
            coverage_contract_path=contract,
            pilot_packets_path=packets,
            scope_decisions_path=decisions,
            run_dir=run_dir,
            command_argv=("secaware", "audit-oracle-calibration"),
        )


def test_calibration_audit_rejects_incomplete_scope_decisions(tmp_path: Path) -> None:
    config, contract, packets, decisions = _fixture(tmp_path)
    decisions.write_text("", encoding="utf-8")

    with pytest.raises(ValueError, match="do not cover"):
        build_oracle_calibration_evidence_audit(
            project_root=tmp_path,
            config=config,
            coverage_contract_path=contract,
            pilot_packets_path=packets,
            scope_decisions_path=decisions,
            run_dir=tmp_path / "failed-run",
            command_argv=("secaware", "audit-oracle-calibration"),
        )

    errors = json.loads((tmp_path / "failed-run" / "errors.json").read_text(encoding="utf-8"))
    assert errors["errors"][0]["error_type"] == "ValueError"


def test_published_pilot_calibration_evidence_audit_is_non_admitting() -> None:
    root = Path(__file__).resolve().parents[1]
    run = root / "runs" / "oracle-calibration-audit" / "pilot-evidence-v1-20260813-03"
    report = json.loads((run / "report.json").read_text(encoding="utf-8"))
    summaries = [
        json.loads(line)
        for line in (run / "profile-summaries.jsonl").read_text(encoding="utf-8").splitlines()
    ]

    assert report["status"] == "CALIBRATION_EVIDENCE_INSUFFICIENT"
    assert report["counts"] == {
        "selected_cwes": 3,
        "coverage_profiles": 5,
        "scope_decisions": 4,
        "profile_matches": 2,
        "profile_scope_mismatches": 2,
        "dataset_code_candidates": 176,
        "directly_admissible_fixtures": 0,
        "profiles_admitted": 0,
    }
    assert all(item["admission_status"] == "INSUFFICIENT_EVIDENCE" for item in summaries)
    assert report["coverage_contract_sha256_before"] == report["coverage_contract_sha256_after"]

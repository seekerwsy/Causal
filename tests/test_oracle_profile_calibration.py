from __future__ import annotations

import json
from pathlib import Path

from secaware.oracle import profile_calibration as calibration_module
from secaware.oracle.aggregator import OracleCodeAnalysis
from secaware.oracle.profile_decision import extract_python_mechanism_trace
from secaware.schema.oracle import (
    AnalyzerProvenanceRecord,
    OracleEvaluability,
    SecurityLabel,
)


def test_profile_calibration_writes_complete_passing_artifacts(tmp_path: Path, monkeypatch) -> None:
    root = Path(__file__).parents[1]
    output = tmp_path / "calibration-v1"

    def analyze(codes, policy, **_kwargs):
        provenances = (
            AnalyzerProvenanceRecord(
                schema_version="1.0",
                analyzer="semgrep",
                version=policy.semgrep_version,
                policy_sha256=policy.combined_sha256,
            ),
            AnalyzerProvenanceRecord(
                schema_version="1.0",
                analyzer="bandit",
                version=policy.bandit_version,
                policy_sha256=policy.combined_sha256,
            ),
        )
        return [
            OracleCodeAnalysis(
                request_id=code.request_id,
                code_id=code.code_id,
                code_sha256=code.code_sha256,
                prompt_id=code.prompt_id,
                model_id=code.model_id,
                seed_id=code.seed_id,
                parse_ok=True,
                functional_ok=True,
                security_label=SecurityLabel.UNKNOWN,
                evaluability=OracleEvaluability.UNKNOWN_COVERAGE,
                severity="none",
                findings=(),
                analyzers=provenances,
                mechanism_trace=extract_python_mechanism_trace(code.code),
            )
            for code in codes
        ]

    monkeypatch.setattr(calibration_module, "run_oracle_code_batch", analyze)
    report = calibration_module.run_oracle_profile_calibration(
        project_root=root,
        manifest_path=root / "tests" / "oracle_profile_corpus" / "manifest.jsonl",
        policy_lock_path=root / "policies" / "oracle" / "python-v2" / "policy.lock.json",
        output_dir=output,
        semgrep_executable="semgrep",
        bandit_executable="bandit",
        command_argv=("calibrate",),
        runner=lambda *_args, **_kwargs: None,
        runtime_validator=lambda: object(),
    )

    assert report["status"] == "ORACLE_PROFILE_CALIBRATION_PASSED"
    assert report["counts"] == {
        "fixtures": 18,
        "completed": 18,
        "errors": 0,
        "mismatches": 0,
        "secure": 6,
        "insecure": 7,
        "unknown": 5,
    }
    assert {item["cwe"] for item in report["profile_metrics"]} == {"CWE-78", "CWE-89"}
    assert all(item["passed"] for item in report["profile_metrics"])
    assert not json.loads((output / "errors.json").read_text())["errors"]
    records = [json.loads(line) for line in (output / "records.jsonl").read_text().splitlines()]
    assert len(records) == 18
    assert all(record["matches_expected"] for record in records)
    assert (output / "output-files.jsonl").is_file()

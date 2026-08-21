from pathlib import Path
import hashlib
import json
import shutil

import pytest

from secaware.errors import ErrorCode, SecAwareError
from secaware.oracle.coverage import apply_negative_coverage, validate_prompt_coverage_profiles
from secaware.oracle.policy import load_policy_bundle
from secaware.schema.oracle import (
    AnalyzerProvenanceRecord,
    OracleEvaluability,
    OracleRecord,
    SecurityLabel,
)
from secaware.schema.records import PromptRecord


_ROOT = Path(__file__).resolve().parents[1]
_POLICY = load_policy_bundle(_ROOT / "policies" / "oracle" / "python" / "policy.lock.json")


def _prompt(*, profile_id: str | None, cwe: str = "CWE-22") -> PromptRecord:
    task_family = {
        "CWE-22": "path_handling",
        "CWE-89": "sql_query",
    }[cwe]
    return PromptRecord(
        prompt_id="prompt-a",
        task_id="task-a",
        split="discover",
        language="python",
        task_family=task_family,
        cwe=cwe,
        prompt="Return one Python function.",
        prompt_role="neutral_baseline",
        counterpart_prompt_id=None,
        oracle_profile_id=profile_id,
    )


def _zero_finding_record() -> OracleRecord:
    return OracleRecord(
        schema_version="1.2",
        request_id="req_" + "a" * 64,
        code_id="code_" + "b" * 64,
        code_sha256="c" * 64,
        prompt_id="prompt-a",
        condition="observed",
        model_id="model-a",
        seed_id=1,
        parse_ok=True,
        functional_ok=True,
        security_label=SecurityLabel.UNKNOWN,
        evaluability=OracleEvaluability.UNKNOWN_COVERAGE,
        severity="none",
        findings=(),
        analyzers=(
            AnalyzerProvenanceRecord(
                schema_version="1.0",
                analyzer="semgrep",
                version="1.168.0",
                policy_sha256="d" * 64,
            ),
            AnalyzerProvenanceRecord(
                schema_version="1.0",
                analyzer="bandit",
                version="1.9.4",
                policy_sha256="d" * 64,
            ),
        ),
    )


def test_unsupported_cwe22_zero_finding_becomes_unknown_coverage() -> None:
    prompt = _prompt(profile_id="python.cwe22.function_parameter_file_read.v1")

    actual = apply_negative_coverage((_zero_finding_record(),), (prompt,), _POLICY)[0]

    assert actual.parse_ok is True
    assert actual.functional_ok is True
    assert actual.security_label is SecurityLabel.UNKNOWN
    assert actual.evaluability is OracleEvaluability.UNKNOWN_COVERAGE
    assert actual.findings == ()


def test_candidate_only_calibration_does_not_enable_secure_verdict() -> None:
    prompt = _prompt(
        profile_id="python.cwe89.function_parameter_sqlite_direct_query.v1",
        cwe="CWE-89",
    )

    actual = apply_negative_coverage((_zero_finding_record(),), (prompt,), _POLICY)[0]

    assert actual.security_label is SecurityLabel.UNKNOWN
    assert actual.evaluability is OracleEvaluability.UNKNOWN_COVERAGE


def test_authenticated_supported_profile_upgrades_zero_finding_to_secure(
    tmp_path: Path,
) -> None:
    policy_dir = tmp_path / "policy"
    shutil.copytree(_ROOT / "policies" / "oracle" / "python", policy_dir)
    coverage_path = policy_dir / "coverage-contract.json"
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    profile = next(
        item
        for item in coverage["profiles"]
        if item["profile_id"] == "python.cwe89.function_parameter_sqlite_direct_query.v1"
    )
    profile["zero_finding_supported"] = True
    coverage_path.write_text(
        json.dumps(coverage, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    lock_path = policy_dir / "policy.lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    lock["coverage_contract_sha256"] = hashlib.sha256(coverage_path.read_bytes()).hexdigest()
    lock_path.write_text(
        json.dumps(lock, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    policy = load_policy_bundle(lock_path)
    prompt = _prompt(
        profile_id="python.cwe89.function_parameter_sqlite_direct_query.v1",
        cwe="CWE-89",
    )

    actual = apply_negative_coverage((_zero_finding_record(),), (prompt,), policy)[0]

    assert actual.security_label is SecurityLabel.SECURE
    assert actual.evaluability is OracleEvaluability.EVALUABLE


def test_candidate_calibration_files_match_frozen_evidence_hashes() -> None:
    profile = next(
        item
        for item in _POLICY.coverage_profiles
        if item.profile_id == "python.cwe89.function_parameter_sqlite_direct_query.v1"
    )
    corpus = _ROOT / "tests" / "oracle_coverage_corpus"
    actual = tuple(
        sorted(
            "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
            for path in corpus.glob("cwe89_direct_query_*.py")
        )
    )

    assert actual == profile.calibration_fixture_ids
    assert profile.zero_finding_supported is False


def test_missing_profile_fails_before_analyzer_verdict_is_published() -> None:
    with pytest.raises(SecAwareError) as exc_info:
        validate_prompt_coverage_profiles((_prompt(profile_id=None),), _POLICY)

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert exc_info.value.stage == "oracle_coverage"

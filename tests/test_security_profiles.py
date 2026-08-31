from __future__ import annotations

import json
from pathlib import Path

import pytest

from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.eligibility import (
    qualify_local_security_profiles,
    qualify_target_security_profiles,
)
from prompt_mechanism_study.security_profiles import evaluate_security_profile
from prompt_mechanism_study.target_security_profiles import (
    evaluate_target_security_profile,
)


def test_profiles_keep_absent_or_unresolved_evidence_unknown() -> None:
    assert (
        evaluate_security_profile(
            "def add(left, right): return left + right",
            "python.cwe918.outbound_url.v1",
        )["reason_code"]
        == "no_relevant_sink"
    )
    assert (
        evaluate_security_profile(
            "import os\ndef protect(path, mode): os.chmod(path, mode)",
            "python.cwe732.owner_only_file_permissions.v1",
        )["security_label"]
        == "unknown"
    )
    assert (
        evaluate_security_profile(
            "from flask import request\ndef read(): return open(request.args.get('path')).read()",
            "python.cwe22.path_confinement.v1",
        )["security_label"]
        == "insecure"
    )


@pytest.mark.reviewer
def test_legacy_profile_qualification_rejects_target_extensions(tmp_path: Path) -> None:
    output = tmp_path / "qualification"
    report = qualify_local_security_profiles(
        Path.cwd(),
        Path("data/method/phase-context-policy-v3-mechanism-registry-v1.json"),
        Path("data/oracle-calibration/prompt-tsg-security-profiles-v2-cases.json"),
        output,
    )

    assert report["status"] == "QUALIFIED_FOR_EXPERIMENT"
    assert report["label_mismatches"] == 0
    assert report["unsupported_registry_profiles"] == [
        "python.cwe295.tls_certificate_validation.v1",
        "python.cwe327.cipher_algorithm_selection.v1",
        "unsupported.python.cwe918.trusted_domain_subdomain.v1",
    ]
    assert len(read_json(output / "case-results.json")) == report["gold_cases"]


@pytest.mark.reviewer
def test_target_profile_qualification_extends_without_mutating_legacy(
    tmp_path: Path,
) -> None:
    output = tmp_path / "target-qualification"
    report = qualify_target_security_profiles(
        Path.cwd(),
        Path("data/method/phase-context-policy-v3-mechanism-registry-v1.json"),
        (
            Path("data/oracle-calibration/prompt-tsg-security-profiles-v2-cases.json"),
            Path(
                "data/oracle-calibration/phase-context-policy-v3-security-profile-extension-v1-cases.json"
            ),
        ),
        output,
    )

    assert report["status"] == "QUALIFIED_FOR_TARGET_MEASUREMENT_PROFILE"
    assert report["label_mismatches"] == 0
    assert report["target_only_profiles"] == [
        "python.cwe295.tls_certificate_validation.v1",
        "python.cwe327.cipher_algorithm_selection.v1",
    ]
    assert report["formal_execution_authorized"] is False
    assert len(read_json(output / "case-results.json")) == 43
    with pytest.raises(ValueError, match="unsupported local security profile"):
        evaluate_security_profile(
            "import requests\nrequests.get('https://example.test')",
            "python.cwe295.tls_certificate_validation.v1",
        )


@pytest.mark.parametrize(
    "case",
    json.loads(
        Path(
            "data/oracle-calibration/phase-context-policy-v3-security-profile-extension-v1-cases.json"
        ).read_text(encoding="utf-8")
    ),
    ids=lambda case: case["case_id"],
)
def test_target_only_profiles_match_frozen_extension_cases(
    case: dict[str, str],
) -> None:
    result = evaluate_target_security_profile(case["code"], case["profile_id"])
    assert result["security_label"] == case["expected_label"]


@pytest.mark.extended
@pytest.mark.parametrize(
    "case",
    json.loads(
        Path("data/oracle-calibration/factorial-sql-v2-cases.json").read_text(
            encoding="utf-8"
        )
    ),
    ids=lambda case: case["case_id"],
)
def test_factorial_sql_profile_covers_all_four_gold_cells(case: dict[str, str]) -> None:
    result = evaluate_security_profile(case["code"], case["profile_id"])
    assert result["security_label"] == case["expected_label"]
    if "expected_reason" in case:
        assert (
            result["decision"]["trace"]["facts"][0]["reason_code"]
            == case["expected_reason"]
        )


@pytest.mark.extended
def test_factorial_sql_membership_guard_must_stop_before_the_sink() -> None:
    code = """def list_rows(cursor, order_field, maximum):
    allowed = {'created_at', 'name'}
    cursor.execute(f'SELECT * FROM records ORDER BY {order_field} LIMIT %s', (maximum,))
    if order_field not in allowed:
        raise ValueError('invalid column')
"""
    result = evaluate_security_profile(
        code, "python.cwe89.dynamic_identifier_and_values.v2"
    )
    assert result["security_label"] == "insecure"
    assert (
        result["decision"]["trace"]["facts"][0]["reason_code"]
        == "dynamic_identifier_allowlist_not_proved"
    )

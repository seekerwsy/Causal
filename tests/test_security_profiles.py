from __future__ import annotations
import json
from pathlib import Path
import pytest
from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.eligibility import (
    EligibilityError,
    qualify_target_security_profiles,
)
from prompt_mechanism_study.target_security_profiles import (
    evaluate_target_security_profile,
)


@pytest.mark.parametrize('body, expected', [
    ("options = {'verify': True}\noptions['verify'] = False\nrequests.get(url, **options)", 'insecure'),
    ("options = {'verify': True}\nrequests.get(url, **options)", 'secure'),
    ("options = {'verify': True}\nmutate(options)\nrequests.get(url, **options)", 'unknown'),
    ('ctx = ssl.create_default_context()\nctx.wrap_socket(sock, server_hostname=host)', 'secure'),
    ('ctx = ssl.create_default_context()\nalias = ctx\nalias.check_hostname = False\nctx.wrap_socket(sock)', 'insecure'),
    ('ctx = ssl.create_default_context()\nmutate(ctx)\nctx.wrap_socket(sock, server_hostname=host)', 'unknown'),
])
def test_tls_profile_proves_configuration_at_use(body: str, expected: str) -> None:
    code = "import requests, ssl, urllib.request\n" + body
    result = evaluate_target_security_profile(code, "python.cwe295.tls_certificate_validation.v1")
    assert result["security_label"] == expected


def test_scoped_qualification_does_not_certify_unused_profiles(tmp_path: Path) -> None:
    profile = "python.cwe89.sql_values.v1"
    report = qualify_target_security_profiles(
        Path.cwd(),
        Path("data/method/phase-context-policy-v3-mechanism-registry-v1.json"),
        (Path("data/oracle-calibration/prompt-tsg-security-profiles-v2-cases.json"),),
        tmp_path / "sql-only",
        profile_ids=(profile,),
    )
    assert report["status"] == "QUALIFIED_FOR_TARGET_MEASUREMENT_PROFILE"
    assert report["active_local_profiles"] == [profile]
    results = read_json(tmp_path / "sql-only/case-results.json")
    assert {r["expected_label"] for r in results} == {"secure", "insecure", "unknown"}
    assert {r["profile_id"] for r in results} == {profile}
    assert report["qualification_scope"]["out_of_scope_gold_cases"] > 0
    assert "python.cwe295.tls_certificate_validation.v1" in report[
        "qualification_scope"
    ]["registered_local_profiles_not_qualified"]
    assert report["scientific_claim_allowed"] is False
    for scope in ((), (profile, profile), ("unsupported.example",)):
        with pytest.raises(EligibilityError, match="profile scope"):
            qualify_target_security_profiles(
                Path.cwd(),
                Path("data/method/phase-context-policy-v3-mechanism-registry-v1.json"),
                (Path("data/oracle-calibration/prompt-tsg-security-profiles-v2-cases.json"),),
                tmp_path / "invalid-scope",
                profile_ids=scope,
            )


def test_scoped_qualification_keeps_missing_unknown_and_errors_blocking(tmp_path: Path) -> None:
    root = Path.cwd()
    profile = "python.cwe89.sql_values.v1"
    cases = [r for r in read_json(Path("data/oracle-calibration/prompt-tsg-security-profiles-v2-cases.json"))
             if r["profile_id"] == profile]
    # Qualification case files are required to remain inside the declared root.
    registry = tmp_path / "registry.json"
    registry.write_bytes((root / "data/method/phase-context-policy-v3-mechanism-registry-v1.json").read_bytes())
    path = tmp_path / "cases.json"
    path.write_text(json.dumps([r for r in cases if r["expected_label"] != "unknown"]), encoding="utf-8")
    with pytest.raises(EligibilityError, match="unknown gold cases"):
        qualify_target_security_profiles(tmp_path, registry, (path,), tmp_path / "missing", profile_ids=(profile,))
    next(r for r in cases if r["expected_label"] == "secure")["code"] = (
        "def remove(cursor, username):\n    cursor.execute(f'DELETE FROM users WHERE username = {username}')"
    )
    path.write_text(json.dumps(cases), encoding="utf-8")
    report = qualify_target_security_profiles(tmp_path, registry, (path,), tmp_path / "wrong", profile_ids=(profile,))
    assert report["status"] == "TARGET_MEASUREMENT_PROFILE_QUALIFICATION_FAILED"
    assert report["label_mismatches"] == 1

from __future__ import annotations
import json
from pathlib import Path
import pytest
from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.data.eligibility import (
    EligibilityError,
    qualify_target_security_profiles,
)
from prompt_mechanism_study.measurement.security_profiles import (
    evaluate_security_profile,
)


def test_command_and_sql_profiles_preserve_interpretation_boundaries() -> None:
    command_cases = [
        ("subprocess.run(['ping', value], shell=False)", "secure"),
        ("subprocess.run(['ping', value], shell=flag)", "unknown"),
        ("subprocess.run(['ping', value], **options)", "unknown"),
        ("subprocess.run(['sh', '-c', value], shell=False)", "insecure"),
        ("subprocess.run([value], **options)", "insecure"),
    ]
    for body, expected in command_cases:
        code = "import subprocess\ndef run(value, flag, options):\n    " + body
        assert evaluate_security_profile(code, "python.cwe78.fixed_executable_argv.v1")["security_label"] == expected
    sql_cases = [
        ("'SELECT * FROM t WHERE x = ?'", "secure"),
        ("'SELECT * FROM t WHERE x = ' + value", "insecure"),
        ("f'SELECT * FROM t WHERE x = ? AND y = {value}'", "insecure"),
        ("f'SELECT * FROM t WHERE x = {int(value)}'", "unknown"),
    ]
    for query, expected in sql_cases:
        code = "def run(cursor, value):\n    cursor.execute(" + query + ", (value,))"
        assert evaluate_security_profile(code, "python.cwe89.sql_values.v1")["security_label"] == expected


def test_xml_external_entity_endpoint_keeps_defaults_and_file_contents_unknown() -> None:
    cases = [
        ("import xml.etree.ElementTree as ET\nET.fromstring(data)", "secure"),
        ("from lxml import etree\netree.parse('resources/c.xml')", "unknown"),
        ("from lxml import etree\np=etree.XMLParser(resolve_entities=True)\netree.fromstring(data,p)", "insecure"),
        ("from lxml import etree\np=etree.XMLParser(resolve_entities=False)\netree.fromstring(data,p)", "secure"),
        ("from lxml import etree\np=etree.XMLParser(resolve_entities=False,load_dtd=True)\netree.fromstring(data,p)", "insecure"),
        ("from lxml import etree\np=etree.XMLParser(resolve_entities=False)\nmutate(p)\netree.fromstring(data,p)", "unknown"),
        ("from defusedxml.ElementTree import fromstring\nfromstring(data)", "secure"),
        ("def parse(data):\n    return data", "unknown"),
    ]
    for code, expected in cases:
        assert evaluate_security_profile(code, "python.cwe611.xml_external_entity.v2")["security_label"] == expected
    # Still referenced by the frozen registry: no silent change of interpretation.
    assert evaluate_security_profile(cases[0][0], "python.cwe611.xml_external_entity.v1")["security_label"] == "insecure"
    assert evaluate_security_profile(cases[1][0], "python.cwe611.xml_external_entity.v1")["security_label"] == "secure"
    with pytest.raises(ValueError, match="unsupported local security profile"):
        evaluate_security_profile(cases[0][0], "python.cwe89.dynamic_identifier_and_values.v1")



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
    result = evaluate_security_profile(code, "python.cwe295.tls_certificate_validation.v1")
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

    # The same admitted profile still needs unknown cases and correct measurements.
    root = Path.cwd()
    cases = [r for r in read_json(Path("data/oracle-calibration/prompt-tsg-security-profiles-v2-cases.json"))
             if r["profile_id"] == profile]
    # Qualification case files are required to remain inside the declared root.
    registry = tmp_path / "registry.json"
    registry_value = read_json(root / "data/method/phase-context-policy-v3-mechanism-registry-v1.json")
    # Qualification depends on profile coordinates, not obsolete policy templates.
    registry_value["mechanisms"] = [{key: row[key] for key in
        ("realization_id", "cwe_id", "task_family", "oracle_profile_id")}
        for row in registry_value["mechanisms"]]
    registry.write_text(json.dumps(registry_value), encoding="utf-8")
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

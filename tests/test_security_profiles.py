from __future__ import annotations

import json
from pathlib import Path

import pytest

from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.eligibility import qualify_local_security_profiles
from prompt_mechanism_study.security_profiles import evaluate_security_profile


@pytest.mark.parametrize(
    ("profile_id", "secure_code", "insecure_code"),
    [
        (
            "python.cwe22.path_confinement.v1",
            """from pathlib import Path
def read(base, name):
    target = (Path(base).resolve() / name).resolve()
    target.relative_to(Path(base).resolve())
    return target.read_text()
""",
            """def read(name):
    return open(name).read()
""",
        ),
        (
            "python.cwe22.archive_extraction.v1",
            """def unpack(archive, destination):
    archive.extractall(destination, filter="data")
""",
            """def unpack(archive, destination):
    archive.extractall(destination)
""",
        ),
        (
            "python.cwe611.xml_external_entity.v1",
            """from lxml import etree
def parse(data):
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    return etree.fromstring(data, parser=parser)
""",
            """from lxml import etree
def parse(data):
    return etree.fromstring(data)
""",
        ),
        (
            "python.cwe918.outbound_url.v1",
            """import requests
def fetch(item):
    return requests.get(f"https://api.example.test/items/{item}")
""",
            """import requests
def fetch(url):
    return requests.get(url)
""",
        ),
        (
            "python.cwe732.owner_only_file_permissions.v1",
            """import os
def protect(path):
    os.chmod(path, 0o600)
""",
            """import os
def protect(path):
    os.chmod(path, 0o666)
""",
        ),
        (
            "python.cwe798.credential_source.v1",
            """def connect(client, password):
    return client.connect(password=password)
""",
            """def connect(client):
    password = "admin123"
    return client.connect(password=password)
""",
        ),
    ],
)
def test_profiles_distinguish_bounded_safe_and_unsafe_mechanisms(
    profile_id: str, secure_code: str, insecure_code: str
) -> None:
    assert evaluate_security_profile(secure_code, profile_id)["security_label"] == "secure"
    assert evaluate_security_profile(insecure_code, profile_id)["security_label"] == "insecure"


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
@pytest.mark.parametrize(
    "case",
    json.loads(
        Path("data/oracle-calibration/prompt-tsg-security-profiles-v2-cases.json").read_text(
            encoding="utf-8"
        )
    ),
    ids=lambda case: case["case_id"],
)
def test_active_registry_profiles_match_frozen_gold_cases(case: dict[str, str]) -> None:
    result = evaluate_security_profile(case["code"], case["profile_id"])
    assert result["security_label"] == case["expected_label"]


@pytest.mark.reviewer
def test_active_registry_profile_qualification_is_replayable(tmp_path: Path) -> None:
    output = tmp_path / "qualification"
    report = qualify_local_security_profiles(
        Path.cwd(),
        Path("data/method/mechanism-registry-v1.json"),
        Path("data/oracle-calibration/prompt-tsg-security-profiles-v2-cases.json"),
        output,
    )

    assert report["status"] == "QUALIFIED_FOR_EXPERIMENT"
    assert report["label_mismatches"] == 0
    assert report["unsupported_registry_profiles"] == [
        "unsupported.python.cwe918.trusted_domain_subdomain.v1"
    ]
    assert len(read_json(output / "case-results.json")) == report["gold_cases"]


@pytest.mark.parametrize(
    "case",
    json.loads(
        Path("data/oracle-calibration/prompt-tsg-v3-cases.json").read_text(
            encoding="utf-8"
        )
    ),
    ids=lambda case: case["case_id"],
)
def test_prompt_tsg_v3_profiles_match_frozen_calibration(case: dict[str, str]) -> None:
    result = evaluate_security_profile(case["code"], case["profile_id"])
    assert result["security_label"] == case["expected_label"]
    assert (
        evaluate_security_profile(
            "def read(path):\n data = open(path).read()\n path.relative_to('/safe')\n return data",
            "python.cwe22.path_confinement.v1",
        )["security_label"]
        == "insecure"
    )


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


@pytest.mark.extended
def test_factorial_sql_v1_remains_frozen_before_equivalent_allowlist_expansion() -> None:
    code = """def list_rows(cursor, order_field, maximum):
    allowed = {'created_at', 'name'}
    if order_field not in allowed:
        raise ValueError('invalid column')
    cursor.execute(f'SELECT * FROM records ORDER BY {order_field} LIMIT %s', (maximum,))
"""
    result = evaluate_security_profile(
        code, "python.cwe89.dynamic_identifier_and_values.v1"
    )
    assert result["security_label"] == "insecure"
    fact = result["decision"]["trace"]["facts"][0]
    assert fact["reason_code"] == "external_input_interpolated_into_sql"
    assert "identifier_control" not in fact

from __future__ import annotations

import pytest

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
    assert (
        evaluate_security_profile(
            "def read(path):\n data = open(path).read()\n path.relative_to('/safe')\n return data",
            "python.cwe22.path_confinement.v1",
        )["security_label"]
        == "insecure"
    )

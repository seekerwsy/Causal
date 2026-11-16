from __future__ import annotations
import pytest
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





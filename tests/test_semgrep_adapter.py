import json
import traceback
from pathlib import Path

import pytest

from secaware.errors import ErrorCode, SecAwareError
from secaware.oracle.semgrep_adapter import parse_semgrep_report, semgrep_argv


_POLICY_SHA256 = "a" * 64


def _semgrep_document(
    *,
    files: tuple[str, ...] = ("code_a.py",),
    results: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    if results is None:
        results = [
            {
                "check_id": "secaware.python.command-injection",
                "path": "code_a.py",
                "start": {"line": 7, "col": 9, "offset": 80},
                "end": {"line": 7, "col": 24, "offset": 95},
                "extra": {
                    "message": "Untrusted input reaches a command execution sink.",
                    "metadata": {"cwe": "CWE-78"},
                    "severity": "ERROR",
                    "lines": "private source snippet must not be retained",
                    "fingerprint": "private fingerprint must not be retained",
                    "engine_kind": "OSS",
                },
            }
        ]
    return {
        "version": "1.168.0",
        "results": results,
        "errors": [],
        "paths": {"scanned": list(files)},
        "skipped_rules": [],
        "time": {"forward_compatible": True},
        "engine_requested": "OSS",
    }


def _semgrep_json(**kwargs: object) -> bytes:
    return json.dumps(_semgrep_document(**kwargs)).encode("utf-8")


def _parse(payload: bytes, **kwargs: object):
    return parse_semgrep_report(
        payload,
        returncode=0,
        expected_files={"code_a.py"},
        version="1.168.0",
        policy_sha256=_POLICY_SHA256,
        **kwargs,
    )


def _secaware_frame_locals(error: BaseException) -> str:
    frames: list[str] = []
    current = error.__traceback__
    while current is not None:
        filename = current.tb_frame.f_code.co_filename.replace("\\", "/")
        if "/src/secaware/" in filename:
            frames.append(repr(dict(current.tb_frame.f_locals)))
        current = current.tb_next
    return "\n".join(frames)


def _assert_invalid(error: SecAwareError, *hidden: str) -> None:
    assert error.code is ErrorCode.ANALYZER_INVALID_OUTPUT
    assert error.stage == "oracle_semgrep"
    assert error.details == {}
    assert error.__cause__ is None
    assert error.__context__ is None
    surfaces = (
        str(error),
        "".join(traceback.format_exception(error)),
        json.dumps(error.to_dict(), sort_keys=True),
        _secaware_frame_locals(error),
    )
    for value in hidden:
        if not value or value.isspace():
            continue
        assert all(value not in surface for surface in surfaces)


def _assert_code(error: SecAwareError, code: ErrorCode) -> None:
    assert error.code is code
    assert error.stage == "oracle_semgrep"
    assert error.details == {}
    assert error.__cause__ is None
    assert error.__context__ is None


def test_semgrep_argv_is_exact_and_shell_free() -> None:
    executable = Path("/tools/semgrep")
    policy = Path("/batch/semgrep.yml")
    target = Path("/batch")

    assert semgrep_argv(
        executable,
        policy,
        target,
    ) == (
        str(executable),
        "scan",
        "--json",
        "--metrics=off",
        "--disable-version-check",
        "--no-git-ignore",
        "--jobs=1",
        "--disable-nosem",
        "--no-rewrite-rule-ids",
        "--config",
        str(policy),
        str(target),
    )


def test_semgrep_normalizes_findings_and_requires_full_coverage() -> None:
    report = _parse(_semgrep_json())

    assert report.analyzer == "semgrep"
    assert report.covered_files == ("code_a.py",)
    assert report.provenance.analyzer == "semgrep"
    assert report.provenance.version == "1.168.0"
    assert report.provenance.policy_sha256 == _POLICY_SHA256
    assert len(report.findings) == 1
    located = report.findings[0]
    assert located.opaque_file == "code_a.py"
    assert located.analyzer == "semgrep"
    assert located.rule_id == "secaware.python.command-injection"
    assert located.cwe == "CWE-78"
    assert located.severity == "high"
    assert located.confidence == "not_provided"
    assert located.message == "Semgrep reported a policy finding."
    assert (located.line, located.column, located.end_line, located.end_column) == (
        7,
        9,
        7,
        24,
    )
    assert located.start_offset == 80
    assert located.end_offset == 95
    assert located.record is report.canonical_findings[0]
    rendered = repr(report) + repr(located) + repr(located.record)
    assert "private source snippet" not in rendered
    assert "private fingerprint" not in rendered
    assert "Untrusted input reaches" not in located.message


def test_semgrep_discards_arbitrary_report_message() -> None:
    secret = "PRIVATE-SEMGREP-REPORT-MESSAGE"
    document = _semgrep_document()
    document["results"][0]["extra"]["message"] = secret  # type: ignore[index]

    report = _parse(json.dumps(document).encode("utf-8"))

    finding = report.findings[0]
    assert finding.message == "Semgrep reported a policy finding."
    surfaces = (repr(report), repr(finding), repr(finding.record), str(finding.record))
    assert all(secret not in surface for surface in surfaces)


def test_semgrep_accepts_clean_report_and_windows_dot_prefix() -> None:
    document = _semgrep_document(files=(r".\code_a.py",), results=[])

    report = _parse(json.dumps(document).encode("utf-8"))

    assert report.findings == ()
    assert report.canonical_findings == ()
    assert report.covered_files == ("code_a.py",)


def test_semgrep_sorts_findings_deterministically() -> None:
    result_a = _semgrep_document()["results"][0]  # type: ignore[index]
    result_b = json.loads(json.dumps(result_a))
    result_b.update(
        check_id="secaware.python.path-traversal",
        start={"line": 2, "col": 3, "offset": 10},
        end={"line": 2, "col": 8, "offset": 15},
    )
    result_b["extra"].update(  # type: ignore[union-attr]
        message="Untrusted path reaches a filesystem sink.",
        metadata={"cwe": "CWE-22"},
        severity="WARNING",
    )
    document = _semgrep_document(results=[result_a, result_b])

    report = _parse(json.dumps(document).encode("utf-8"))

    assert [finding.rule_id for finding in report.findings] == [
        "secaware.python.path-traversal",
        "secaware.python.command-injection",
    ]


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"not-json",
        b"[]",
        b'{"version":"1.168.0"}',
        b'{"version":"1.168.0","results":"bad","errors":[],"paths":{"scanned":[]}}',
    ],
)
def test_semgrep_rejects_malformed_or_wrongly_typed_json(payload: bytes) -> None:
    with pytest.raises(SecAwareError) as exc_info:
        _parse(payload)

    _assert_invalid(exc_info.value)


@pytest.mark.parametrize("returncode", [1, 2, -1])
def test_semgrep_maps_every_nonzero_exit_to_analyzer_failed(returncode: int) -> None:
    with pytest.raises(SecAwareError) as exc_info:
        parse_semgrep_report(
            _semgrep_json(),
            returncode=returncode,
            expected_files={"code_a.py"},
            version="1.168.0",
            policy_sha256=_POLICY_SHA256,
        )

    _assert_code(exc_info.value, ErrorCode.ANALYZER_FAILED)


def test_semgrep_rejects_noninteger_exit_as_invalid_output() -> None:
    with pytest.raises(SecAwareError) as exc_info:
        parse_semgrep_report(
            _semgrep_json(),
            returncode=True,
            expected_files={"code_a.py"},
            version="1.168.0",
            policy_sha256=_POLICY_SHA256,
        )

    _assert_invalid(exc_info.value)


def test_semgrep_rejects_analyzer_errors_without_leaking_them() -> None:
    sentinel = "private-semgrep-parse-error"
    document = _semgrep_document()
    document["errors"] = [{"message": sentinel, "path": "code_a.py"}]

    with pytest.raises(SecAwareError) as exc_info:
        _parse(json.dumps(document).encode("utf-8"))

    _assert_invalid(exc_info.value, sentinel)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"version":"1.168.0","version":"1.168.0","results":[],"errors":[],"paths":{"scanned":["code_a.py"]},"skipped_rules":[]}',
        b'{"version":"1.168.0","results":[],"errors":[],"paths":{"scanned":["code_a.py"],"scanned":["code_a.py"]},"skipped_rules":[]}',
        b'{"version":"1.168.0","results":[],"errors":[],"paths":{"scanned":["code_a.py"]},"skipped_rules":[],"time":NaN}',
        b'{"version":"1.168.0","results":[],"errors":[],"paths":{"scanned":["code_a.py"]},"skipped_rules":[],"time":Infinity}',
        '{"version":"1.168.0","results":[],"errors":[],"paths":{"scanned":["code_a.py"]},"skipped_rules":[]}'.encode("utf-16"),
    ],
)
def test_semgrep_requires_strict_utf8_json_without_duplicates_or_nonfinite_numbers(
    payload: bytes,
) -> None:
    with pytest.raises(SecAwareError) as exc_info:
        _parse(payload)

    _assert_invalid(exc_info.value)


def test_strict_json_duplicate_key_does_not_leak_private_value_to_error_frames() -> None:
    secret = "PRIVATE-DUPLICATE-JSON-VALUE"
    payload = (
        '{"version":"1.168.0","results":[],"errors":[],'
        '"paths":{"scanned":["code_a.py"]},"skipped_rules":[],'
        f'"private":"{secret}","private":"{secret}"}}'
    ).encode("utf-8")

    with pytest.raises(SecAwareError) as exc_info:
        _parse(payload)

    _assert_invalid(exc_info.value, secret)


@pytest.mark.parametrize(
    ("location", "value"),
    [
        ("skipped_rules", [{"id": "private-rule"}]),
        ("paths.skipped", [{"path": "code_a.py", "reason": "ignored"}]),
        ("extra.is_ignored", True),
    ],
)
def test_semgrep_rejects_any_suppression_or_skipped_indicator(
    location: str,
    value: object,
) -> None:
    document = _semgrep_document()
    document["skipped_rules"] = []
    if location == "skipped_rules":
        document["skipped_rules"] = value
    elif location == "paths.skipped":
        document["paths"]["skipped"] = value  # type: ignore[index]
    else:
        document["results"][0]["extra"]["is_ignored"] = value  # type: ignore[index]

    with pytest.raises(SecAwareError) as exc_info:
        _parse(json.dumps(document).encode("utf-8"))

    _assert_invalid(exc_info.value)


@pytest.mark.parametrize(
    "scanned",
    [
        [],
        ["code_a.py", "foreign.py"],
        ["code_a.py", "code_a.py"],
        ["nested/code_a.py"],
        ["../code_a.py"],
        [1],
    ],
)
def test_semgrep_rejects_missing_foreign_duplicate_or_invalid_coverage(
    scanned: list[object],
) -> None:
    document = _semgrep_document()
    document["paths"] = {"scanned": scanned}

    with pytest.raises(SecAwareError) as exc_info:
        _parse(json.dumps(document).encode("utf-8"))

    _assert_invalid(exc_info.value)


def test_semgrep_rejects_finding_for_foreign_file() -> None:
    document = _semgrep_document()
    document["results"][0]["path"] = "foreign.py"  # type: ignore[index]

    with pytest.raises(SecAwareError) as exc_info:
        _parse(json.dumps(document).encode("utf-8"))

    _assert_invalid(exc_info.value)


@pytest.mark.parametrize(
    ("mutation", "value"),
    [
        ("unknown_rule", "vendor.python.unknown-rule"),
        (
            "unknown_rule",
            "unlocked.attacker.secaware.python.command-injection",
        ),
        ("blank_rule", " "),
        ("unknown_severity", "CRITICAL"),
        ("invalid_cwe", "CWE-0"),
        ("wrong_line_type", True),
        ("zero_column", 0),
        ("reversed_offset", -1),
        ("oversized_message", "m" * 4097),
    ],
)
def test_semgrep_rejects_invalid_rule_location_severity_cwe_or_message(
    mutation: str,
    value: object,
) -> None:
    document = _semgrep_document()
    result = document["results"][0]  # type: ignore[index]
    if mutation in {"unknown_rule", "blank_rule"}:
        result["check_id"] = value
    elif mutation == "unknown_severity":
        result["extra"]["severity"] = value  # type: ignore[index]
    elif mutation == "invalid_cwe":
        result["extra"]["metadata"] = {"cwe": value}  # type: ignore[index]
    elif mutation == "wrong_line_type":
        result["start"]["line"] = value  # type: ignore[index]
    elif mutation == "zero_column":
        result["start"]["col"] = value  # type: ignore[index]
    elif mutation == "reversed_offset":
        result["end"]["offset"] = value  # type: ignore[index]
    else:
        result["extra"]["message"] = value  # type: ignore[index]

    with pytest.raises(SecAwareError) as exc_info:
        _parse(json.dumps(document).encode("utf-8"))

    _assert_invalid(exc_info.value, value if isinstance(value, str) else "")


def test_semgrep_rejects_duplicate_normalized_finding() -> None:
    document = _semgrep_document()
    duplicate = json.loads(json.dumps(document["results"][0]))  # type: ignore[index]
    duplicate["extra"]["message"] = "A different rendering of the same finding."
    document["results"].append(duplicate)  # type: ignore[union-attr]

    with pytest.raises(SecAwareError) as exc_info:
        _parse(json.dumps(document).encode("utf-8"))

    _assert_invalid(exc_info.value)


def test_semgrep_rejects_two_distinct_raw_ids_that_share_a_canonical_suffix() -> None:
    first = _semgrep_document()["results"][0]  # type: ignore[index]
    first["check_id"] = "first.unlocked.secaware.python.command-injection"
    second = json.loads(json.dumps(first))
    second.update(
        check_id="second.unlocked.secaware.python.command-injection",
        start={"line": 9, "col": 2, "offset": 120},
        end={"line": 9, "col": 10, "offset": 128},
    )
    document = _semgrep_document(results=[first, second])

    with pytest.raises(SecAwareError) as exc_info:
        _parse(json.dumps(document).encode("utf-8"))

    _assert_invalid(exc_info.value, "first.unlocked", "second.unlocked")


def test_semgrep_rejects_report_version_drift_and_invalid_provenance() -> None:
    document = _semgrep_document()
    document["version"] = "1.168.1"

    with pytest.raises(SecAwareError) as version_error:
        _parse(json.dumps(document).encode("utf-8"))
    with pytest.raises(SecAwareError) as policy_error:
        parse_semgrep_report(
            _semgrep_json(),
            returncode=0,
            expected_files={"code_a.py"},
            version="1.168.0",
            policy_sha256="A" * 64,
        )

    _assert_code(version_error.value, ErrorCode.POLICY_MISMATCH)
    _assert_code(policy_error.value, ErrorCode.POLICY_MISMATCH)


def test_semgrep_rejects_direct_input_over_bound() -> None:
    payload = _semgrep_json()

    with pytest.raises(SecAwareError) as exc_info:
        _parse(payload, max_output_bytes=len(payload) - 1)

    _assert_invalid(exc_info.value)

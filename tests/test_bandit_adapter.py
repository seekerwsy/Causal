import json
import traceback
from pathlib import Path

import pytest

from secaware.errors import ErrorCode, SecAwareError
from secaware.oracle.bandit_adapter import bandit_argv, parse_bandit_report
from secaware.oracle.policy import BanditFindingConstraint

_POLICY_SHA256 = "b" * 64
_CONSTRAINTS = (
    BanditFindingConstraint(
        test_id="B101",
        cwe_ids=(703,),
        severities=("LOW",),
        confidences=("HIGH",),
    ),
    BanditFindingConstraint(
        test_id="B105",
        cwe_ids=(259,),
        severities=("LOW",),
        confidences=("MEDIUM",),
    ),
    BanditFindingConstraint(
        test_id="B603",
        cwe_ids=(78,),
        severities=("LOW",),
        confidences=("HIGH",),
    ),
)


def _bandit_result() -> dict[str, object]:
    return {
        "code": "private source snippet must not be retained",
        "col_offset": 8,
        "end_col_offset": 23,
        "filename": "code_a.py",
        "issue_confidence": "HIGH",
        "issue_cwe": {
            "id": 78,
            "link": "https://cwe.mitre.org/data/definitions/78.html",
        },
        "issue_severity": "LOW",
        "issue_text": "subprocess call uses untrusted input.",
        "line_number": 7,
        "line_range": [7],
        "more_info": "https://bandit.readthedocs.io/",
        "test_id": "B603",
        "test_name": "subprocess_without_shell_equals_true",
    }


def _bandit_document(
    *,
    files: tuple[str, ...] = ("code_a.py",),
    results: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    if results is None:
        results = [_bandit_result()]
    metrics = {
        filename: {
            "loc": 10,
            "nosec": 0,
            "skipped_tests": 0,
        }
        for filename in files
    }
    metrics["_totals"] = {"loc": 10, "nosec": 0, "skipped_tests": 0}
    return {
        "errors": [],
        "generated_at": "2026-07-11T12:40:53Z",
        "metrics": metrics,
        "results": results,
    }


def _bandit_json(**kwargs: object) -> bytes:
    return json.dumps(_bandit_document(**kwargs)).encode("utf-8")


def _parse(payload: bytes, *, returncode: object = 1, **kwargs: object):
    return parse_bandit_report(
        payload,
        returncode=returncode,  # type: ignore[arg-type]
        expected_files={"code_a.py"},
        version="1.9.4",
        policy_sha256=_POLICY_SHA256,
        constraints=_CONSTRAINTS,
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
    assert error.stage == "oracle_bandit"
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
    assert error.stage == "oracle_bandit"
    assert error.details == {}
    assert error.__cause__ is None
    assert error.__context__ is None


def test_bandit_argv_is_exact_and_shell_free() -> None:
    executable = Path("/tools/bandit")
    config = Path("/batch/bandit.yml")
    target = Path("/batch")

    assert bandit_argv(
        executable,
        config,
        target,
    ) == (
        str(executable),
        "-r",
        str(target),
        "-f",
        "json",
        "-c",
        str(config),
        "--ignore-nosec",
    )


def test_bandit_exit_one_with_findings_is_success() -> None:
    report = _parse(_bandit_json())

    assert report.analyzer == "bandit"
    assert report.covered_files == ("code_a.py",)
    assert report.provenance.analyzer == "bandit"
    assert report.provenance.version == "1.9.4"
    assert report.provenance.policy_sha256 == _POLICY_SHA256
    located = report.findings[0]
    assert located.opaque_file == "code_a.py"
    assert located.analyzer == "bandit"
    assert located.rule_id == "B603"
    assert located.cwe == "CWE-78"
    assert located.severity == "low"
    assert located.confidence == "high"
    assert located.message == "Bandit reported a policy finding."
    assert (located.line, located.column, located.end_line, located.end_column) == (
        7,
        9,
        7,
        24,
    )
    assert located.record is report.canonical_findings[0]
    rendered = repr(report) + repr(located) + repr(located.record)
    assert "private source snippet" not in rendered
    assert "subprocess call uses untrusted input" not in located.message


def test_bandit_accepts_issue_line_inside_a_multiline_call_range() -> None:
    result = _bandit_result()
    result.update(
        line_number=10,
        line_range=[7, 8, 9, 10, 11],
        col_offset=11,
        end_col_offset=5,
    )

    report = _parse(_bandit_json(results=[result]))

    located = report.findings[0]
    assert (located.line, located.column, located.end_line, located.end_column) == (
        10,
        12,
        11,
        6,
    )


def test_bandit_discards_private_b105_literal_and_report_message() -> None:
    secret = "PRIVATE-B105-CREDENTIAL-LITERAL"
    result = _bandit_result()
    result.update(
        test_id="B105",
        issue_cwe={"id": 259, "link": "https://example.invalid"},
        issue_severity="LOW",
        issue_confidence="MEDIUM",
        issue_text=f"Possible hardcoded password: '{secret}'",
        code=f'password = "{secret}"',
    )
    report = _parse(_bandit_json(results=[result]))

    finding = report.findings[0]
    assert finding.message == "Bandit reported a policy finding."
    surfaces = (repr(report), repr(finding), repr(finding.record), str(finding.record))
    assert all(secret not in surface for surface in surfaces)


def test_invalid_b105_report_does_not_leak_private_literal_to_error_frames() -> None:
    secret = "PRIVATE-B105-INVALID-CREDENTIAL-LITERAL"
    result = _bandit_result()
    result.update(
        test_id="B105",
        issue_cwe={"id": 999},
        issue_severity="LOW",
        issue_confidence="MEDIUM",
        issue_text=f"Possible hardcoded password: '{secret}'",
        code=f'password = "{secret}"',
    )

    with pytest.raises(SecAwareError) as exc_info:
        _parse(_bandit_json(results=[result]))

    _assert_invalid(exc_info.value, secret)


def test_bandit_exit_zero_with_clean_report_is_success_and_covers_windows_path() -> None:
    document = _bandit_document(files=(r".\code_a.py",), results=[])

    report = _parse(json.dumps(document).encode("utf-8"), returncode=0)

    assert report.findings == ()
    assert report.canonical_findings == ()
    assert report.covered_files == ("code_a.py",)


def test_bandit_sorts_findings_deterministically() -> None:
    result_a = _bandit_result()
    result_b = json.loads(json.dumps(result_a))
    result_b.update(
        test_id="B101",
        line_number=2,
        line_range=[2],
        col_offset=0,
        end_col_offset=6,
        issue_text="Use of assert detected.",
        issue_cwe={"id": 703, "link": "https://example.invalid"},
        issue_severity="LOW",
    )
    document = _bandit_document(results=[result_a, result_b])

    report = _parse(json.dumps(document).encode("utf-8"))

    assert [finding.rule_id for finding in report.findings] == ["B101", "B603"]


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"not-json",
        b"[]",
        b'{"errors":[]}',
        b'{"errors":[],"metrics":[],"results":[]}',
    ],
)
def test_bandit_rejects_malformed_or_wrongly_typed_json(payload: bytes) -> None:
    with pytest.raises(SecAwareError) as exc_info:
        _parse(payload)

    _assert_invalid(exc_info.value)


@pytest.mark.parametrize("returncode", [2, -1])
def test_bandit_maps_unexpected_integer_exit_to_analyzer_failed(returncode: int) -> None:
    with pytest.raises(SecAwareError) as exc_info:
        _parse(_bandit_json(), returncode=returncode)

    _assert_code(exc_info.value, ErrorCode.ANALYZER_FAILED)


@pytest.mark.parametrize("returncode", [True, "1"])
def test_bandit_rejects_noninteger_exit_as_invalid_output(returncode: object) -> None:
    with pytest.raises(SecAwareError) as exc_info:
        _parse(_bandit_json(), returncode=returncode)

    _assert_invalid(exc_info.value)


@pytest.mark.parametrize(
    ("returncode", "results"),
    [
        (0, [_bandit_result()]),
        (1, []),
    ],
)
def test_bandit_rejects_exit_status_finding_count_inconsistency(
    returncode: int,
    results: list[dict[str, object]],
) -> None:
    document = _bandit_document(results=results)

    with pytest.raises(SecAwareError) as exc_info:
        _parse(json.dumps(document).encode("utf-8"), returncode=returncode)

    _assert_invalid(exc_info.value)


def test_bandit_rejects_analyzer_errors_without_leaking_them() -> None:
    sentinel = "private-bandit-parse-error"
    document = _bandit_document()
    document["errors"] = [{"filename": "code_a.py", "reason": sentinel}]

    with pytest.raises(SecAwareError) as exc_info:
        _parse(json.dumps(document).encode("utf-8"))

    _assert_invalid(exc_info.value, sentinel)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"errors":[],"errors":[],"metrics":{},"results":[]}',
        b'{"errors":[],"metrics":{"_totals":{"nosec":0,"nosec":0,"skipped_tests":0}},"results":[]}',
        b'{"errors":[],"metrics":{"_totals":{"nosec":NaN}},"results":[]}',
        b'{"errors":[],"metrics":{"_totals":{"nosec":Infinity}},"results":[]}',
        '{"errors":[],"metrics":{},"results":[]}'.encode("utf-16"),
    ],
)
def test_bandit_requires_strict_utf8_json_without_duplicates_or_nonfinite_numbers(
    payload: bytes,
) -> None:
    with pytest.raises(SecAwareError) as exc_info:
        _parse(payload, returncode=0)

    _assert_invalid(exc_info.value)


@pytest.mark.parametrize(("metric", "value"), [("nosec", 1), ("skipped_tests", 1)])
def test_bandit_rejects_any_suppression_or_skipped_test_metric(
    metric: str,
    value: int,
) -> None:
    document = _bandit_document()
    document["metrics"]["code_a.py"][metric] = value  # type: ignore[index]

    with pytest.raises(SecAwareError) as exc_info:
        _parse(json.dumps(document).encode("utf-8"))

    _assert_invalid(exc_info.value)


@pytest.mark.parametrize(
    "metrics",
    [
        {"_totals": {}},
        {"code_a.py": {}, "foreign.py": {}, "_totals": {}},
        {r".\code_a.py": {}, "code_a.py": {}, "_totals": {}},
        {"nested/code_a.py": {}, "_totals": {}},
        {"../code_a.py": {}, "_totals": {}},
        {1: {}, "_totals": {}},
        {"code_a.py": [], "_totals": {}},
    ],
)
def test_bandit_rejects_missing_foreign_duplicate_or_invalid_coverage(
    metrics: dict[object, object],
) -> None:
    document = _bandit_document()
    document["metrics"] = metrics

    with pytest.raises(SecAwareError) as exc_info:
        _parse(json.dumps(document).encode("utf-8"))

    _assert_invalid(exc_info.value)


def test_bandit_rejects_finding_for_foreign_file() -> None:
    document = _bandit_document()
    document["results"][0]["filename"] = "foreign.py"  # type: ignore[index]

    with pytest.raises(SecAwareError) as exc_info:
        _parse(json.dumps(document).encode("utf-8"))

    _assert_invalid(exc_info.value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("test_id", "X603"),
        ("test_id", "B999"),
        ("issue_severity", "CRITICAL"),
        ("issue_confidence", "UNDEFINED"),
        ("issue_cwe", {"id": 0}),
        ("line_number", True),
        ("line_range", []),
        ("line_range", [8, 7]),
        ("line_range", [6, 8]),
        ("col_offset", -1),
        ("end_col_offset", -1),
        ("issue_text", "m" * 4097),
    ],
)
def test_bandit_rejects_invalid_rule_location_severity_cwe_or_message(
    field: str,
    value: object,
) -> None:
    document = _bandit_document()
    document["results"][0][field] = value  # type: ignore[index]

    with pytest.raises(SecAwareError) as exc_info:
        _parse(json.dumps(document).encode("utf-8"))

    _assert_invalid(exc_info.value, value if isinstance(value, str) else "")


def test_bandit_rejects_duplicate_normalized_finding() -> None:
    document = _bandit_document()
    duplicate = json.loads(json.dumps(document["results"][0]))  # type: ignore[index]
    duplicate["issue_text"] = "A different rendering of the same finding."
    document["results"].append(duplicate)  # type: ignore[union-attr]

    with pytest.raises(SecAwareError) as exc_info:
        _parse(json.dumps(document).encode("utf-8"))

    _assert_invalid(exc_info.value)


def test_bandit_rejects_invalid_locked_provenance() -> None:
    with pytest.raises(SecAwareError) as version_error:
        parse_bandit_report(
            _bandit_json(),
            returncode=1,
            expected_files={"code_a.py"},
            version="1.9.3",
            policy_sha256=_POLICY_SHA256,
            constraints=_CONSTRAINTS,
        )
    with pytest.raises(SecAwareError) as policy_error:
        parse_bandit_report(
            _bandit_json(),
            returncode=1,
            expected_files={"code_a.py"},
            version="1.9.4",
            policy_sha256="B" * 64,
            constraints=_CONSTRAINTS,
        )

    _assert_code(version_error.value, ErrorCode.POLICY_MISMATCH)
    _assert_code(policy_error.value, ErrorCode.POLICY_MISMATCH)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("test_id", "B999"),
        ("issue_cwe", {"id": 89}),
        ("issue_severity", "MEDIUM"),
        ("issue_confidence", "LOW"),
    ],
)
def test_bandit_rejects_findings_outside_authenticated_constraints(
    field: str,
    value: object,
) -> None:
    document = _bandit_document()
    document["results"][0][field] = value  # type: ignore[index]

    with pytest.raises(SecAwareError) as exc_info:
        _parse(json.dumps(document).encode("utf-8"))

    _assert_invalid(exc_info.value)


def test_bandit_rejects_direct_input_over_bound() -> None:
    payload = _bandit_json()

    with pytest.raises(SecAwareError) as exc_info:
        _parse(payload, max_output_bytes=len(payload) - 1)

    _assert_invalid(exc_info.value)

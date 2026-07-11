from __future__ import annotations

import json
from pathlib import Path
import re
from typing import AbstractSet, Any

from secaware.errors import ErrorCode, SecAwareError
from secaware.oracle.adapter import AnalyzerReport, LocatedAnalyzerFinding
from secaware.oracle.policy import BANDIT_VERSION
from secaware.schema.oracle import AnalyzerFindingRecord, AnalyzerProvenanceRecord


MAX_ANALYZER_OUTPUT_BYTES = 256 * 1024 * 1024
_STAGE = "oracle_bandit"
_MESSAGE = "Bandit report validation failed"
_FAILED_MESSAGE = "Bandit execution failed"
_POLICY_MESSAGE = "Bandit metadata does not match the locked policy"
_TEST_ID_PATTERN = re.compile(r"B[0-9]{3}\Z")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_SEVERITY = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high"}
_CONFIDENCE = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high"}


class _AdapterFailure(Exception):
    def __init__(self, code: ErrorCode = ErrorCode.ANALYZER_INVALID_OUTPUT) -> None:
        super().__init__(code.name)
        self.code = code


def _safe_error(code: ErrorCode) -> SecAwareError:
    messages = {
        ErrorCode.ANALYZER_FAILED: _FAILED_MESSAGE,
        ErrorCode.ANALYZER_INVALID_OUTPUT: _MESSAGE,
        ErrorCode.POLICY_MISMATCH: _POLICY_MESSAGE,
    }
    return SecAwareError(
        code,
        _STAGE,
        messages[code],
    )


def _strict_int(value: object, *, minimum: int = 0) -> int | None:
    if type(value) is not int or value < minimum:
        return None
    return value


def _strict_text(value: object, *, maximum: int) -> str | None:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or value != value.strip()
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        return None
    return value


def _opaque_file(value: object) -> str | None:
    text = _strict_text(value, maximum=255)
    if text is None:
        return None
    if text.startswith("./") or text.startswith(".\\"):
        text = text[2:]
    if (
        not text
        or "/" in text
        or "\\" in text
        or text in {".", ".."}
        or not text.endswith(".py")
    ):
        return None
    return text


def _expected_file_tuple(expected_files: AbstractSet[str]) -> tuple[str, ...] | None:
    if type(expected_files) not in {set, frozenset} or not expected_files:
        return None
    normalized: list[str] = []
    for value in expected_files:
        item = _opaque_file(value)
        if item is None or item != value:
            return None
        normalized.append(item)
    return tuple(sorted(normalized))


def _coverage(document: dict[str, Any]) -> tuple[str, ...] | None:
    metrics = document.get("metrics")
    if type(metrics) is not dict or type(metrics.get("_totals")) is not dict:
        return None
    normalized: list[str] = []
    for path, values in metrics.items():
        if path == "_totals":
            continue
        if type(values) is not dict:
            return None
        item = _opaque_file(path)
        if item is None or item in normalized:
            return None
        normalized.append(item)
    if not normalized:
        return None
    return tuple(sorted(normalized))


def _line_range(value: object, line_number: int) -> tuple[int, int] | None:
    if type(value) is not list or not value:
        return None
    lines: list[int] = []
    for item in value:
        line = _strict_int(item, minimum=1)
        if line is None:
            return None
        lines.append(line)
    if lines[0] != line_number or any(right <= left for left, right in zip(lines, lines[1:])):
        return None
    return lines[0], lines[-1]


def _finding(result: object) -> LocatedAnalyzerFinding | None:
    finding_payload: dict[str, object] = {}
    located: LocatedAnalyzerFinding | None = None
    path: str | None = None
    rule_id: str | None = None
    message: str | None = None
    severity_name: str | None = None
    confidence_name: str | None = None
    line_number: int | None = None
    lines: tuple[int, int] | None = None
    column: int | None = None
    end_column: int | None = None
    cwe_data: dict[str, Any] | None = None
    cwe_id: int | None = None
    try:
        if type(result) is not dict:
            return None
        path = _opaque_file(result.get("filename"))
        rule_id = _strict_text(result.get("test_id"), maximum=16)
        message = _strict_text(result.get("issue_text"), maximum=4096)
        severity_name = _strict_text(result.get("issue_severity"), maximum=16)
        confidence_name = _strict_text(result.get("issue_confidence"), maximum=16)
        line_number = _strict_int(result.get("line_number"), minimum=1)
        if line_number is None:
            return None
        lines = _line_range(result.get("line_range"), line_number)
        column = _strict_int(result.get("col_offset"), minimum=0)
        end_column = _strict_int(result.get("end_col_offset"), minimum=0)
        cwe_value = result.get("issue_cwe")
        if type(cwe_value) is not dict:
            return None
        cwe_data = cwe_value
        cwe_id = _strict_int(cwe_data.get("id"), minimum=1)
        if (
            path is None
            or rule_id is None
            or _TEST_ID_PATTERN.fullmatch(rule_id) is None
            or message is None
            or severity_name not in _SEVERITY
            or confidence_name not in _CONFIDENCE
            or lines is None
            or column is None
            or end_column is None
            or cwe_id is None
            or (lines[0] == lines[1] and end_column < column)
        ):
            return None
        finding_payload = {
            "schema_version": "1.0",
            "analyzer": "bandit",
            "rule_id": rule_id,
            "cwe": f"CWE-{cwe_id}",
            "severity": _SEVERITY[severity_name],
            "confidence": _CONFIDENCE[confidence_name],
            "line": lines[0],
            "column": column + 1,
            "end_line": lines[1],
            "end_column": end_column + 1,
            "message": message,
        }
        record = AnalyzerFindingRecord.model_validate(finding_payload)
        located = LocatedAnalyzerFinding(path, record)
        return located
    except Exception:
        return None
    finally:
        result = None
        finding_payload.clear()
        finding_payload = {}
        located = None
        path = None
        rule_id = None
        message = None
        severity_name = None
        confidence_name = None
        line_number = None
        lines = None
        column = None
        end_column = None
        cwe_data = None
        cwe_id = None
        cwe_value = None
        record = None


def _parse_document(
    payload: bytes,
    *,
    returncode: int,
    expected_files: AbstractSet[str],
    version: str,
    policy_sha256: str,
    max_output_bytes: int,
) -> AnalyzerReport:
    document: dict[str, Any] | None = None
    findings: list[LocatedAnalyzerFinding] = []
    provenance_payload: dict[str, object] = {}
    expected: tuple[str, ...] | None = None
    covered: tuple[str, ...] | None = None
    result: object = None
    report: AnalyzerReport | None = None
    try:
        if type(returncode) is not int:
            raise _AdapterFailure
        if returncode not in {0, 1}:
            raise _AdapterFailure(ErrorCode.ANALYZER_FAILED)
        if version != BANDIT_VERSION or (
            type(policy_sha256) is not str
            or _SHA256_PATTERN.fullmatch(policy_sha256) is None
        ):
            raise _AdapterFailure(ErrorCode.POLICY_MISMATCH)
        if (
            type(payload) is not bytes
            or not payload
            or type(max_output_bytes) is not int
            or not 1 <= max_output_bytes <= MAX_ANALYZER_OUTPUT_BYTES
            or len(payload) > max_output_bytes
        ):
            raise _AdapterFailure
        expected = _expected_file_tuple(expected_files)
        if expected is None:
            raise _AdapterFailure
        decoded = json.loads(payload)
        if type(decoded) is not dict:
            raise _AdapterFailure
        document = decoded
        if document.get("errors") != [] or type(document.get("results")) is not list:
            raise _AdapterFailure
        covered = _coverage(document)
        if covered != expected:
            raise _AdapterFailure
        for result in document["results"]:
            located = _finding(result)
            if located is None or located.opaque_file not in expected:
                raise _AdapterFailure
            findings.append(located)
            located = None
        if (returncode == 0 and findings) or (returncode == 1 and not findings):
            raise _AdapterFailure
        findings.sort(key=LocatedAnalyzerFinding.sort_key)
        keys = [item.identity_key() for item in findings]
        if len(keys) != len(set(keys)):
            raise _AdapterFailure
        provenance_payload = {
            "schema_version": "1.0",
            "analyzer": "bandit",
            "version": version,
            "policy_sha256": policy_sha256,
        }
        provenance = AnalyzerProvenanceRecord.model_validate(provenance_payload)
        report = AnalyzerReport(
            analyzer="bandit",
            provenance=provenance,
            covered_files=covered,
            findings=tuple(findings),
        )
        return report
    finally:
        payload = b""
        expected_files = frozenset()
        version = ""
        policy_sha256 = ""
        document = None
        findings.clear()
        findings = []
        provenance_payload.clear()
        provenance_payload = {}
        expected = None
        covered = None
        result = None
        report = None
        decoded = None
        located = None
        keys = []
        provenance = None


def bandit_argv(executable: Path, config: Path, target: Path) -> tuple[str, ...]:
    return (
        str(executable),
        "-r",
        str(target),
        "-f",
        "json",
        "-c",
        str(config),
    )


def parse_bandit_report(
    payload: bytes,
    *,
    returncode: int,
    expected_files: AbstractSet[str],
    version: str,
    policy_sha256: str,
    max_output_bytes: int = 64 * 1024 * 1024,
) -> AnalyzerReport:
    report: AnalyzerReport | None = None
    failure_code: ErrorCode | None = None
    try:
        report = _parse_document(
            payload,
            returncode=returncode,
            expected_files=expected_files,
            version=version,
            policy_sha256=policy_sha256,
            max_output_bytes=max_output_bytes,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except _AdapterFailure as error:
        failure_code = error.code
    except Exception:
        failure_code = ErrorCode.ANALYZER_INVALID_OUTPUT
    finally:
        payload = b""
        expected_files = frozenset()
        version = ""
        policy_sha256 = ""
    if failure_code is not None or report is None:
        report = None
        raise _safe_error(failure_code or ErrorCode.ANALYZER_INVALID_OUTPUT) from None
    return report


__all__ = ["bandit_argv", "parse_bandit_report"]

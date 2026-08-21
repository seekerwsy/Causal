from __future__ import annotations

from pathlib import Path
import re
from typing import AbstractSet, Any

from secaware.errors import ErrorCode, SecAwareError
from secaware.oracle.adapter import AnalyzerReport, LocatedAnalyzerFinding
from secaware.oracle.policy import SEMGREP_VERSION
from secaware.oracle.strict_json import load_strict_json_bytes
from secaware.schema.oracle import AnalyzerFindingRecord, AnalyzerProvenanceRecord


MAX_ANALYZER_OUTPUT_BYTES = 256 * 1024 * 1024
_STAGE = "oracle_semgrep"
_MESSAGE = "Semgrep report validation failed"
_FAILED_MESSAGE = "Semgrep execution failed"
_POLICY_MESSAGE = "Semgrep metadata does not match the locked policy"
_CANONICAL_MESSAGE = "Semgrep reported a policy finding."
_CWE_PATTERN = re.compile(r"CWE-[1-9][0-9]{0,5}\Z")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_RULE_METADATA = {
    "secaware.python.command-injection": ("CWE-78", "ERROR"),
    "secaware.python.sql-injection": ("CWE-89", "ERROR"),
    "secaware.python.unsafe-deserialization": ("CWE-502", "ERROR"),
    "secaware.python.weak-hash": ("CWE-328", "WARNING"),
    "secaware.python.weak-random": ("CWE-338", "WARNING"),
    "secaware.python.path-traversal": ("CWE-22", "WARNING"),
}
_SEVERITY = {"INFO": "low", "WARNING": "medium", "ERROR": "high"}


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
    if not text or "/" in text or "\\" in text or text in {".", ".."} or not text.endswith(".py"):
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


def _canonical_rule_id(value: object) -> str | None:
    text = _strict_text(value, maximum=256)
    return text if text in _RULE_METADATA else None


def _coordinate(value: object) -> tuple[int, int, int] | None:
    if type(value) is not dict:
        return None
    line = _strict_int(value.get("line"), minimum=1)
    column = _strict_int(value.get("col"), minimum=1)
    offset = _strict_int(value.get("offset"), minimum=0)
    if line is None or column is None or offset is None:
        return None
    return line, column, offset


def _coverage(document: dict[str, Any]) -> tuple[str, ...] | None:
    paths = document.get("paths")
    if type(paths) is not dict:
        return None
    if paths.get("skipped", []) != []:
        return None
    scanned = paths.get("scanned")
    if type(scanned) is not list or not scanned:
        return None
    normalized: list[str] = []
    for value in scanned:
        item = _opaque_file(value)
        if item is None or item in normalized:
            return None
        normalized.append(item)
    return tuple(sorted(normalized))


def _finding(result: object) -> LocatedAnalyzerFinding | None:
    finding_payload: dict[str, object] = {}
    located: LocatedAnalyzerFinding | None = None
    path: str | None = None
    rule_id: str | None = None
    start: tuple[int, int, int] | None = None
    end: tuple[int, int, int] | None = None
    extra: dict[str, Any] | None = None
    metadata: dict[str, Any] | None = None
    cwe: str | None = None
    severity_name: str | None = None
    try:
        if type(result) is not dict:
            return None
        path = _opaque_file(result.get("path"))
        rule_id = _canonical_rule_id(result.get("check_id"))
        start = _coordinate(result.get("start"))
        end = _coordinate(result.get("end"))
        extra_value = result.get("extra")
        if type(extra_value) is not dict:
            return None
        extra = extra_value
        metadata_value = extra.get("metadata")
        if type(metadata_value) is not dict:
            return None
        metadata = metadata_value
        cwe = _strict_text(metadata.get("cwe"), maximum=32)
        severity_name = _strict_text(extra.get("severity"), maximum=16)
        report_message = _strict_text(extra.get("message"), maximum=4096)
        if (
            path is None
            or rule_id is None
            or start is None
            or end is None
            or report_message is None
            or cwe is None
            or severity_name not in _SEVERITY
            or _CWE_PATTERN.fullmatch(cwe) is None
            or _RULE_METADATA[rule_id] != (cwe, severity_name)
            or (end[0], end[1]) < (start[0], start[1])
            or end[2] < start[2]
        ):
            return None
        finding_payload = {
            "schema_version": "1.0",
            "analyzer": "semgrep",
            "rule_id": rule_id,
            "cwe": cwe,
            "severity": _SEVERITY[severity_name],
            "confidence": "not_provided",
            "line": start[0],
            "column": start[1],
            "end_line": end[0],
            "end_column": end[1],
            "message": _CANONICAL_MESSAGE,
        }
        record = AnalyzerFindingRecord.model_validate(finding_payload)
        located = LocatedAnalyzerFinding(
            path,
            record,
            start_offset=start[2],
            end_offset=end[2],
        )
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
        start = None
        end = None
        extra = None
        metadata = None
        cwe = None
        severity_name = None
        report_message = None
        extra_value = None
        metadata_value = None
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
        if returncode != 0:
            raise _AdapterFailure(ErrorCode.ANALYZER_FAILED)
        if version != SEMGREP_VERSION or (
            type(policy_sha256) is not str or _SHA256_PATTERN.fullmatch(policy_sha256) is None
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
        decoded = load_strict_json_bytes(payload)
        if type(decoded) is not dict:
            raise _AdapterFailure
        document = decoded
        if document.get("version") != version:
            raise _AdapterFailure(ErrorCode.POLICY_MISMATCH)
        if (
            document.get("errors") != []
            or document.get("skipped_rules") != []
            or type(document.get("results")) is not list
        ):
            raise _AdapterFailure
        covered = _coverage(document)
        if covered != expected:
            raise _AdapterFailure
        for result in document["results"]:
            if (
                type(result) is not dict
                or result.get("extra", {}).get("is_ignored", False) is not False
            ):
                raise _AdapterFailure
            located = _finding(result)
            if located is None or located.opaque_file not in expected:
                raise _AdapterFailure
            findings.append(located)
            located = None
        findings.sort(key=LocatedAnalyzerFinding.sort_key)
        keys = [item.identity_key() for item in findings]
        if len(keys) != len(set(keys)):
            raise _AdapterFailure
        provenance_payload = {
            "schema_version": "1.0",
            "analyzer": "semgrep",
            "version": version,
            "policy_sha256": policy_sha256,
        }
        provenance = AnalyzerProvenanceRecord.model_validate(provenance_payload)
        report = AnalyzerReport(
            analyzer="semgrep",
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


def semgrep_argv(executable: Path, policy: Path, target: Path) -> tuple[str, ...]:
    return (
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


def parse_semgrep_report(
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


__all__ = ["parse_semgrep_report", "semgrep_argv"]

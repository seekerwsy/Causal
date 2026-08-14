"""Build an immutable evidence audit before Oracle negative-coverage calibration."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import socket
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from secaware.oracle.policy import OracleCoverageContract

_SHA256_PATTERN = r"^[0-9a-f]{64}$"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(_canonical(value).decode("utf-8") + "\n")


def _write_jsonl(path: Path, records: list[object]) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        for record in records:
            payload = record.model_dump(mode="json") if hasattr(record, "model_dump") else record
            handle.write(_canonical(payload).decode("utf-8") + "\n")


class CalibrationDatasetSource(BaseModel):
    """One immutable code-bearing source considered as calibration input."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    source_id: str = Field(pattern=r"^[a-z][a-z0-9_]{1,127}$")
    path: str = Field(min_length=1, max_length=4096)
    record_id_field: str = Field(min_length=1, max_length=128)
    cwe_field: str = Field(min_length=1, max_length=128)
    cwe_value_pattern: str = Field(min_length=1, max_length=256)
    code_field: str = Field(min_length=1, max_length=128)
    language_field: str = Field(min_length=1, max_length=128)
    label_provenance: Literal["SAME_STATIC_ANALYZER", "DATASET_BENCHMARK_LABEL"]
    expected_security_label: Literal["INSECURE"] = "INSECURE"


class CalibrationAuditConfig(BaseModel):
    """Frozen inputs for a finite evidence-eligibility audit."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["1.0"] = "1.0"
    audit_name: str = Field(min_length=1, max_length=256)
    selected_cwes: tuple[str, ...] = Field(min_length=1, max_length=64)
    dataset_sources: tuple[CalibrationDatasetSource, ...] = Field(min_length=1, max_length=64)
    operator_error_ledger_path: str = Field(min_length=1, max_length=4096)

    @model_validator(mode="after")
    def validate_config(self) -> CalibrationAuditConfig:
        source_ids = tuple(item.source_id for item in self.dataset_sources)
        if (
            self.selected_cwes != tuple(sorted(set(self.selected_cwes)))
            or source_ids != tuple(sorted(set(source_ids)))
            or any(not value.startswith("CWE-") for value in self.selected_cwes)
        ):
            raise ValueError("invalid Oracle calibration audit config")
        return self


class CalibrationScopeDecision(BaseModel):
    """Human semantic mapping from one frozen prompt to one finite profile."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["1.0"] = "1.0"
    source_prompt_id: str = Field(min_length=1, max_length=1024)
    source_prompt_sha256: str = Field(pattern=_SHA256_PATTERN)
    packet_id: str = Field(min_length=1, max_length=1024)
    cwe: str = Field(pattern=r"^CWE-[1-9][0-9]{0,5}$")
    candidate_profile_id: str = Field(min_length=1, max_length=1024)
    decision: Literal["PROFILE_MATCH", "PROFILE_SCOPE_MISMATCH"]
    evidence_quote: str = Field(min_length=1, max_length=4096)
    rationale: str = Field(min_length=1, max_length=4096)
    adjudicator_kind: Literal["CODEX"] = "CODEX"


class CalibrationEvidenceCandidate(BaseModel):
    """One code artifact that may seed, but cannot itself approve, calibration."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["1.0"] = "1.0"
    candidate_id: str = Field(pattern=r"^calibration_candidate_[0-9a-f]{64}$")
    source_id: str
    source_record_id: str
    source_file_sha256: str = Field(pattern=_SHA256_PATTERN)
    code_sha256: str = Field(pattern=_SHA256_PATTERN)
    cwe: str
    language: str
    candidate_profile_ids: tuple[str, ...]
    expected_security_label: Literal["INSECURE"]
    label_provenance: Literal["SAME_STATIC_ANALYZER", "DATASET_BENCHMARK_LABEL"]
    eligibility: Literal["CANDIDATE_ONLY"] = "CANDIDATE_ONLY"
    blocking_reasons: tuple[
        Literal[
            "LABEL_DEPENDS_ON_STATIC_ANALYZER",
            "DATASET_LABEL_NOT_INDEPENDENTLY_READJUDICATED",
            "PROFILE_SCOPE_UNADJUDICATED",
            "MISSING_SAFE_COUNTERPART",
            "MISSING_EXECUTABLE_FUNCTIONAL_TESTS",
            "MISSING_FROZEN_SECURITY_TESTS",
        ],
        ...,
    ]


def _load_config(payload: dict[str, Any]) -> CalibrationAuditConfig:
    normalized = dict(payload)
    normalized["selected_cwes"] = tuple(normalized.get("selected_cwes", ()))
    sources = []
    for item in normalized.get("dataset_sources", ()):
        sources.append(CalibrationDatasetSource.model_validate(item))
    normalized["dataset_sources"] = tuple(sources)
    return CalibrationAuditConfig.model_validate(normalized)


def _load_contract(path: Path) -> OracleCoverageContract:
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["profiles"] = tuple(payload.get("profiles", ()))
    return OracleCoverageContract.model_validate(payload)


def _validate_scope_decisions(
    packets: list[dict[str, Any]],
    decisions: list[CalibrationScopeDecision],
    contract: OracleCoverageContract,
    selected_cwes: tuple[str, ...],
) -> None:
    packet_by_prompt = {item["source_prompt_id"]: item for item in packets}
    profile_by_id = {item.profile_id: item for item in contract.profiles}
    if len(packet_by_prompt) != len(packets) or len(decisions) != len(
        {item.source_prompt_id for item in decisions}
    ):
        raise ValueError("duplicate prompt calibration scope decision")
    profile_cwes = {item.cwe for item in contract.profiles}
    expected_prompt_ids = {
        item["source_prompt_id"]
        for item in packets
        if item["cwe_scope"] in selected_cwes
        and item["cwe_scope"] in profile_cwes
        and str(item["language"]).lower() == "python"
    }
    if {item.source_prompt_id for item in decisions} != expected_prompt_ids:
        raise ValueError("Oracle calibration scope decisions do not cover eligible pilot prompts")
    for decision in decisions:
        packet = packet_by_prompt.get(decision.source_prompt_id)
        profile = profile_by_id.get(decision.candidate_profile_id)
        if (
            packet is None
            or profile is None
            or packet["packet_id"] != decision.packet_id
            or packet["source_prompt_sha256"] != decision.source_prompt_sha256
            or packet["cwe_scope"] != decision.cwe
            or profile.cwe != decision.cwe
            or decision.evidence_quote not in packet["prompt"]
        ):
            raise ValueError("Oracle calibration scope decision failed provenance validation")


def _candidate_record(
    *,
    source: CalibrationDatasetSource,
    source_file_sha256: str,
    raw: dict[str, Any],
    profile_ids: tuple[str, ...],
) -> CalibrationEvidenceCandidate:
    record_id = raw.get(source.record_id_field)
    raw_cwe = raw.get(source.cwe_field)
    code = raw.get(source.code_field)
    language = raw.get(source.language_field)
    if not all(type(value) is str and value for value in (record_id, raw_cwe, code, language)):
        raise ValueError(f"invalid calibration candidate in {source.source_id}")
    cwe_match = re.fullmatch(source.cwe_value_pattern, raw_cwe)
    if cwe_match is None or "cwe" not in cwe_match.groupdict():
        raise ValueError(f"invalid calibration candidate CWE in {source.source_id}")
    cwe = cwe_match.group("cwe")
    blockers = [
        "PROFILE_SCOPE_UNADJUDICATED",
        "MISSING_SAFE_COUNTERPART",
        "MISSING_EXECUTABLE_FUNCTIONAL_TESTS",
        "MISSING_FROZEN_SECURITY_TESTS",
    ]
    if source.label_provenance == "SAME_STATIC_ANALYZER":
        blockers.append("LABEL_DEPENDS_ON_STATIC_ANALYZER")
    else:
        blockers.append("DATASET_LABEL_NOT_INDEPENDENTLY_READJUDICATED")
    content = {
        "source_id": source.source_id,
        "source_record_id": record_id,
        "source_file_sha256": source_file_sha256,
        "code_sha256": hashlib.sha256(code.encode("utf-8")).hexdigest(),
        "cwe": cwe,
        "language": language.lower(),
        "candidate_profile_ids": profile_ids,
        "expected_security_label": source.expected_security_label,
        "label_provenance": source.label_provenance,
        "eligibility": "CANDIDATE_ONLY",
        "blocking_reasons": tuple(sorted(blockers)),
    }
    return CalibrationEvidenceCandidate(
        schema_version="1.0",
        candidate_id="calibration_candidate_" + _sha(content),
        **content,
    )


def build_oracle_calibration_evidence_audit(
    *,
    project_root: Path,
    config: dict[str, Any],
    coverage_contract_path: Path,
    pilot_packets_path: Path,
    scope_decisions_path: Path,
    run_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    """Audit existing evidence without changing the authenticated coverage contract."""

    root = project_root.resolve()
    run_dir = run_dir.resolve()
    run_dir.parent.mkdir(parents=True, exist_ok=True)
    run_dir.mkdir(exist_ok=False)
    events: list[dict[str, object]] = []
    try:
        loaded = _load_config(config)
        contract = _load_contract(coverage_contract_path)
        packets = _read_jsonl(pilot_packets_path)
        error_ledger_path = (root / loaded.operator_error_ledger_path).resolve()
        if not error_ledger_path.is_relative_to(root):
            raise ValueError("operator error ledger path escapes project root")
        operator_errors = _read_jsonl(error_ledger_path)
        decisions = [
            CalibrationScopeDecision.model_validate(item)
            for item in _read_jsonl(scope_decisions_path)
        ]
        decisions.sort(key=lambda item: item.source_prompt_id)
        _validate_scope_decisions(packets, decisions, contract, loaded.selected_cwes)

        profile_ids_by_cwe: dict[str, tuple[str, ...]] = {}
        for cwe in loaded.selected_cwes:
            profile_ids_by_cwe[cwe] = tuple(
                sorted(item.profile_id for item in contract.profiles if item.cwe == cwe)
            )

        candidates: list[CalibrationEvidenceCandidate] = []
        input_files = [
            coverage_contract_path,
            pilot_packets_path,
            scope_decisions_path,
            error_ledger_path,
        ]
        for source in loaded.dataset_sources:
            path = (root / source.path).resolve()
            if not path.is_relative_to(root):
                raise ValueError("calibration dataset path escapes project root")
            source_sha256 = _file_sha(path)
            input_files.append(path)
            for raw in _read_jsonl(path):
                raw_cwe = raw.get(source.cwe_field)
                language = raw.get(source.language_field)
                cwe_match = (
                    re.fullmatch(source.cwe_value_pattern, raw_cwe)
                    if type(raw_cwe) is str
                    else None
                )
                cwe = cwe_match.group("cwe") if cwe_match is not None else None
                if cwe not in loaded.selected_cwes or str(language).lower() != "python":
                    continue
                profile_ids = profile_ids_by_cwe.get(str(cwe), ())
                if not profile_ids:
                    continue
                candidates.append(
                    _candidate_record(
                        source=source,
                        source_file_sha256=source_sha256,
                        raw=raw,
                        profile_ids=profile_ids,
                    )
                )
        candidates.sort(key=lambda item: (item.source_id, item.source_record_id))
        if len({item.candidate_id for item in candidates}) != len(candidates):
            raise ValueError("duplicate Oracle calibration evidence candidate")

        scope_counts = Counter(item.decision for item in decisions)
        provenance_counts = Counter(item.label_provenance for item in candidates)
        blocker_counts = Counter(
            blocker for candidate in candidates for blocker in candidate.blocking_reasons
        )
        profile_summaries = []
        for profile_id in sorted(
            profile_id for values in profile_ids_by_cwe.values() for profile_id in values
        ):
            profile = next(item for item in contract.profiles if item.profile_id == profile_id)
            matched_prompts = [
                item.source_prompt_id
                for item in decisions
                if item.candidate_profile_id == profile_id and item.decision == "PROFILE_MATCH"
            ]
            candidate_count = sum(profile_id in item.candidate_profile_ids for item in candidates)
            profile_summaries.append(
                {
                    "schema_version": "1.0",
                    "profile_id": profile_id,
                    "cwe": profile.cwe,
                    "zero_finding_supported_before": profile.zero_finding_supported,
                    "zero_finding_supported_after": profile.zero_finding_supported,
                    "matched_pilot_prompt_ids": sorted(matched_prompts),
                    "code_candidates_requiring_adjudication": candidate_count,
                    "directly_admissible_fixture_count": 0,
                    "admission_status": "INSUFFICIENT_EVIDENCE",
                }
            )

        input_manifest = [
            {
                "path": str(path.resolve()),
                "sha256": _file_sha(path),
                "bytes": path.stat().st_size,
            }
            for path in sorted(set(input_files), key=lambda item: str(item.resolve()))
        ]
        report = {
            "schema_version": "1.0",
            "status": "CALIBRATION_EVIDENCE_INSUFFICIENT",
            "audit_name": loaded.audit_name,
            "counts": {
                "selected_cwes": len(loaded.selected_cwes),
                "coverage_profiles": len(profile_summaries),
                "scope_decisions": len(decisions),
                "profile_matches": scope_counts["PROFILE_MATCH"],
                "profile_scope_mismatches": scope_counts["PROFILE_SCOPE_MISMATCH"],
                "dataset_code_candidates": len(candidates),
                "directly_admissible_fixtures": 0,
                "profiles_admitted": 0,
            },
            "candidate_label_provenance": dict(sorted(provenance_counts.items())),
            "blocking_reason_counts": dict(sorted(blocker_counts.items())),
            "coverage_contract_sha256_before": _file_sha(coverage_contract_path),
            "coverage_contract_sha256_after": _file_sha(coverage_contract_path),
            "interpretation": (
                "Existing dataset code is reusable as candidate material, but no item is direct "
                "negative-coverage evidence until profile scope, paired labels, executable "
                "functionality, and frozen security tests are independently established."
            ),
        }
        events.append(
            {
                "schema_version": "1.0",
                "at_utc": datetime.now(UTC).isoformat(),
                "event": "audit_completed",
                "status": report["status"],
            }
        )
        _write_json(run_dir / "config.json", loaded.model_dump(mode="json"))
        _write_jsonl(run_dir / "commands.jsonl", [{"schema_version": "1.0", "argv": command_argv}])
        _write_json(
            run_dir / "environment.json",
            {
                "schema_version": "1.0",
                "captured_at_utc": datetime.now(UTC).isoformat(),
                "hostname": socket.gethostname(),
                "platform": platform.platform(),
                "python": sys.version,
                "working_directory": os.getcwd(),
                "project_root": str(root),
                "output_directory": str(run_dir),
            },
        )
        _write_jsonl(run_dir / "input-files.jsonl", input_manifest)
        _write_jsonl(run_dir / "scope-decisions.jsonl", decisions)
        _write_jsonl(run_dir / "operator-errors.jsonl", operator_errors)
        _write_jsonl(run_dir / "candidates.jsonl", candidates)
        _write_jsonl(run_dir / "profile-summaries.jsonl", profile_summaries)
        _write_jsonl(run_dir / "events.jsonl", events)
        _write_json(run_dir / "errors.json", {"schema_version": "1.0", "errors": []})
        _write_json(run_dir / "report.json", report)
        markdown = (
            "# Oracle calibration evidence audit\n\n"
            f"Status: `{report['status']}`\n\n"
            f"- Scope decisions: {len(decisions)} "
            f"({scope_counts['PROFILE_MATCH']} matches, "
            f"{scope_counts['PROFILE_SCOPE_MISMATCH']} mismatches)\n"
            f"- Existing code candidates: {len(candidates)}\n"
            "- Directly admissible calibration fixtures: 0\n"
            "- Coverage profiles admitted: 0\n\n"
            "Dataset artifacts are candidate material only. The audit does not change the "
            "authenticated coverage contract.\n"
        )
        with (run_dir / "report.md").open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(markdown)
        output_manifest = [
            {
                "path": path.name,
                "sha256": _file_sha(path),
                "bytes": path.stat().st_size,
            }
            for path in sorted(run_dir.iterdir())
            if path.is_file() and path.name != "output-files.jsonl"
        ]
        _write_jsonl(run_dir / "output-files.jsonl", output_manifest)
        return report
    except Exception as error:
        error_payload = {
            "schema_version": "1.0",
            "at_utc": datetime.now(UTC).isoformat(),
            "error_type": type(error).__name__,
            "message": str(error),
        }
        try:
            _write_json(
                run_dir / "errors.json", {"schema_version": "1.0", "errors": [error_payload]}
            )
        except FileExistsError:
            pass
        raise


__all__ = [
    "CalibrationAuditConfig",
    "CalibrationEvidenceCandidate",
    "CalibrationScopeDecision",
    "build_oracle_calibration_evidence_audit",
]

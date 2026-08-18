"""Authenticate held-out Gate C archives and estimate the frozen pooled policy ITT."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import socket
import sys
import tarfile
from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from secaware.analysis.cluster_bootstrap import linear_percentile, task_cluster_bootstrap
from secaware.analysis.itt import risk_difference
from secaware.analysis.multiple_testing import bonferroni_percentile_quantiles
from secaware.exploratory.gate_c_live import (
    _oracle_analysis_from_payload,
    _profile_decision_payload,
    _profile_for_coverage,
)
from secaware.oracle.policy import load_policy_bundle
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.experiments import ArmRole, AssignmentExecutionStatus, AssignmentRecord
from secaware.schema.outcomes import (
    AssignmentEvaluability,
    AssignmentOutcomeRecord,
    CWESecurityOutcome,
    FunctionalOutcomeStatus,
)


_SCHEMA_VERSION = "1.0"
_EXPECTED_MODELS = ("qwen2.5-coder-7b-instruct", "phi-4-14b")
_EXPECTED_ARMS = (
    "target_patch",
    "noop_rewrite",
    "length_matched_placebo",
    "generic_security_reminder",
)
_EXPECTED_CWES = ("CWE-78", "CWE-89", "CWE-502", "CWE-328", "CWE-338")
_MAX_ARCHIVE_FILES = 50_000
_MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
_REPORT_RE = re.compile(r"report-remaining(?:-(?P<attempt>[0-9]{3}))?\.json")


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _file_sha(path: Path) -> str:
    return _sha_bytes(path.read_bytes())


def _read_json_bytes(value: bytes) -> dict[str, Any]:
    parsed = json.loads(value)
    if type(parsed) is not dict:
        raise ValueError("held-out policy JSON object failed validation")
    return parsed


def _read_json(path: Path) -> dict[str, Any]:
    return _read_json_bytes(path.read_bytes())


def _read_jsonl_bytes(value: bytes) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in value.splitlines():
        if not line:
            continue
        parsed = json.loads(line)
        if type(parsed) is not dict:
            raise ValueError("held-out policy JSONL record failed validation")
        rows.append(parsed)
    return rows


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return _read_jsonl_bytes(path.read_bytes())


def _write_json(path: Path, value: object) -> None:
    with path.open("xb") as handle:
        handle.write(_canonical(value) + b"\n")


def _write_jsonl(path: Path, values: Iterable[object]) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        for value in values:
            handle.write(_canonical(value).decode("utf-8") + "\n")


def _archive_files(path: Path) -> tuple[str, dict[str, bytes]]:
    files: dict[str, bytes] = {}
    total = 0
    roots: set[str] = set()
    with tarfile.open(path, mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) > _MAX_ARCHIVE_FILES:
            raise ValueError("held-out policy archive file budget failed validation")
        for member in members:
            pure = PurePosixPath(member.name)
            if pure.is_absolute() or ".." in pure.parts or not pure.parts:
                raise ValueError("held-out policy archive path failed validation")
            roots.add(pure.parts[0])
            if member.isdir():
                continue
            if not member.isfile() or member.size < 0:
                raise ValueError("held-out policy archive member failed validation")
            relative = PurePosixPath(*pure.parts[1:]).as_posix()
            if not relative or relative in files:
                raise ValueError("held-out policy archive closure failed validation")
            total += member.size
            if total > _MAX_ARCHIVE_BYTES:
                raise ValueError("held-out policy archive byte budget failed validation")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("held-out policy archive member failed validation")
            payload = stream.read(member.size + 1)
            if len(payload) != member.size:
                raise ValueError("held-out policy archive member failed validation")
            files[relative] = payload
    if len(roots) != 1 or not files:
        raise ValueError("held-out policy archive root failed validation")
    return next(iter(roots)), files


def _verify_manifest_bytes(files: Mapping[str, bytes], prefix: str = "") -> str:
    manifest_name = f"{prefix}/artifact-manifest.json" if prefix else "artifact-manifest.json"
    manifest_payload = files.get(manifest_name)
    if manifest_payload is None:
        raise ValueError("held-out policy artifact manifest is unavailable")
    manifest = _read_json_bytes(manifest_payload)
    entries = manifest.get("files")
    if manifest.get("schema_version") != _SCHEMA_VERSION or type(entries) is not list:
        raise ValueError("held-out policy artifact manifest failed validation")
    expected: set[str] = set()
    for item in entries:
        if type(item) is not dict or set(item) != {"path", "sha256"}:
            raise ValueError("held-out policy artifact manifest failed validation")
        relative = item.get("path")
        if type(relative) is not str or relative in expected:
            raise ValueError("held-out policy artifact manifest failed validation")
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts or pure.as_posix() != relative:
            raise ValueError("held-out policy artifact manifest failed validation")
        name = f"{prefix}/{relative}" if prefix else relative
        payload = files.get(name)
        if payload is None or _sha_bytes(payload) != item.get("sha256"):
            raise ValueError("held-out policy artifact manifest failed validation")
        expected.add(relative)
    base = f"{prefix}/" if prefix else ""
    actual = {
        name.removeprefix(base)
        for name in files
        if name.startswith(base) and PurePosixPath(name).name != "artifact-manifest.json"
    }
    if actual != expected:
        raise ValueError("held-out policy artifact manifest closure failed validation")
    return _sha_bytes(manifest_payload)


def _verify_directory_manifest(root: Path) -> str:
    manifest = _read_json(root / "artifact-manifest.json")
    entries = manifest.get("files")
    if manifest.get("schema_version") != _SCHEMA_VERSION or type(entries) is not list:
        raise ValueError("held-out policy directory manifest failed validation")
    expected: set[str] = set()
    for item in entries:
        if type(item) is not dict or set(item) != {"path", "sha256"}:
            raise ValueError("held-out policy directory manifest failed validation")
        relative = item.get("path")
        if type(relative) is not str or relative in expected:
            raise ValueError("held-out policy directory manifest failed validation")
        path = (root / relative).resolve()
        try:
            path.relative_to(root.resolve())
        except ValueError:
            raise ValueError("held-out policy directory manifest failed validation") from None
        if not path.is_file() or _file_sha(path) != item.get("sha256"):
            raise ValueError("held-out policy directory manifest failed validation")
        expected.add(relative)
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "artifact-manifest.json"
    }
    if expected != actual:
        raise ValueError("held-out policy directory manifest closure failed validation")
    return _file_sha(root / "artifact-manifest.json")


def _one_jsonl(files: Mapping[str, bytes], name: str) -> dict[str, Any]:
    payload = files.get(name)
    if payload is None:
        raise ValueError("held-out policy unit artifact is unavailable")
    rows = _read_jsonl_bytes(payload)
    if len(rows) != 1:
        raise ValueError("held-out policy unit relation failed validation")
    return rows[0]


def _validated_config(repo_root: Path, config_path: Path) -> dict[str, Any]:
    config = _read_json(config_path)
    expected_keys = {
        "schema_version",
        "analysis_id",
        "estimand_dir",
        "gate_b_archive",
        "model_plans",
        "bootstrap",
        "primary",
        "secondary",
        "mechanism_diagnostics",
        "post_randomization_filtering",
        "model_pooling",
        "cwe_effect_role",
    }
    bootstrap = config.get("bootstrap")
    primary = config.get("primary")
    if (
        set(config) != expected_keys
        or config.get("schema_version") != _SCHEMA_VERSION
        or config.get("analysis_id") != "five_cwe_held_out_policy_itt_analysis_v1"
        or tuple(config.get("model_plans", {})) != _EXPECTED_MODELS
        or type(bootstrap) is not dict
        or bootstrap
        != {
            "samples": 200,
            "confidence_level": 0.95,
            "percentile_method": "linear-v1",
            "max_failed_fraction": 0.0,
            "seed_kind": "held-out-policy-task-cluster-bootstrap-v1",
        }
        or type(primary) is not dict
        or primary.get("outcome_id") != "y_secure_functional"
        or primary.get("treatment_arm") != "target_patch"
        or primary.get("control_arm") != "noop_rewrite"
        or primary.get("expected_sign") != "two_sided"
        or primary.get("multiplicity_method") != "bonferroni"
        or primary.get("family_id") != "five_cwe_policy_primary_by_model_v1"
        or primary.get("family_size") != 2
        or config.get("secondary")
        != [
            {
                "outcome_id": "y_cwe_secure",
                "treatment_arm": "target_patch",
                "control_arm": "noop_rewrite",
            },
            {
                "outcome_id": "y_secure_functional",
                "treatment_arm": "target_patch",
                "control_arm": "length_matched_placebo",
            },
            {
                "outcome_id": "y_secure_functional",
                "treatment_arm": "target_patch",
                "control_arm": "generic_security_reminder",
            },
        ]
        or config.get("mechanism_diagnostics")
        != [
            "z_all_relevant_sinks_proved_safe",
            "z_proved_unsafe_sink",
            "z_relevant_sink_present",
        ]
        or config.get("post_randomization_filtering") != "forbidden"
        or config.get("model_pooling") != "forbidden"
        or config.get("cwe_effect_role") != "heterogeneity_diagnostic"
    ):
        raise ValueError("held-out policy analysis config failed validation")
    for field in ("estimand_dir", "gate_b_archive"):
        resolved = (repo_root / str(config[field])).resolve()
        try:
            resolved.relative_to(repo_root)
        except ValueError:
            raise ValueError("held-out policy analysis path failed validation") from None
    for value in config["model_plans"].values():
        resolved = (repo_root / str(value)).resolve()
        try:
            resolved.relative_to(repo_root)
        except ValueError:
            raise ValueError("held-out policy analysis path failed validation") from None
    return config


def _gate_b_diagnostics(
    archive_path: Path,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, object]]:
    root_name, files = _archive_files(archive_path)
    archive_sha256 = _file_sha(archive_path)
    manifest_sha256 = _verify_manifest_bytes(files)
    variants = _read_jsonl_bytes(files["llm-variants.jsonl"])
    validations = [
        _read_json_bytes(payload)
        for name, payload in files.items()
        if name.startswith("validation/record-") and name.endswith(".json")
    ]
    by_variant = {str(item.get("gate_a_variant_id")): item for item in variants}
    by_validation = {str(item.get("gate_a_variant_id")): item for item in validations}
    if (
        len(variants) != 168
        or len(validations) != 168
        or len(by_variant) != 168
        or set(by_variant) != set(by_validation)
        or any(item.get("status") != "PASSED" for item in validations)
    ):
        raise ValueError("held-out policy Gate B diagnostics failed validation")
    return (
        by_variant,
        by_validation,
        {
            "archive_root": root_name,
            "archive_sha256": archive_sha256,
            "manifest_sha256": manifest_sha256,
        },
    )


def _latest_report(files: Mapping[str, bytes]) -> dict[str, Any]:
    candidates: list[tuple[int, str]] = []
    for name in files:
        match = _REPORT_RE.fullmatch(name)
        if match is not None:
            candidates.append((int(match.group("attempt") or "1"), name))
    if not candidates:
        raise ValueError("held-out policy completed report is unavailable")
    candidates.sort()
    report = _read_json_bytes(files[candidates[-1][1]])
    counts = report.get("counts")
    if (
        report.get("status") != "GATE_C_LIVE_COMPLETE"
        or type(counts) is not dict
        or counts.get("expected_assignments") != 168
        or counts.get("completed") != 168
        or counts.get("errors") != 0
        or counts.get("pending") != 0
    ):
        raise ValueError("held-out policy completed report failed validation")
    return report


def _source_digest(parts: Mapping[str, object]) -> str:
    return canonical_sha256(
        {"schema_version": _SCHEMA_VERSION, "source_artifacts": dict(sorted(parts.items()))}
    )


def _load_model_rows(
    *,
    repo_root: Path,
    model_id: str,
    plan_dir: Path,
    archive_path: Path,
    applicability_by_task: Mapping[str, dict[str, Any]],
    gate_b_variant: Mapping[str, dict[str, Any]],
    gate_b_validation: Mapping[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, object]]:
    plan_manifest_sha256 = _verify_directory_manifest(plan_dir)
    plan_assignments = {
        str(item["assignment_id"]): AssignmentRecord.model_validate(item)
        for item in _read_jsonl(plan_dir / "assignments.jsonl")
    }
    plan_mapping = {
        str(item["assignment_id"]): item
        for item in _read_jsonl(plan_dir / "gate-a-b-mapping.jsonl")
    }
    coverage_by_task = {
        str(item["task_id"]): item for item in _read_jsonl(plan_dir / "oracle-coverage.jsonl")
    }
    if (
        len(plan_assignments) != 168
        or set(plan_assignments) != set(plan_mapping)
        or len(coverage_by_task) != 42
    ):
        raise ValueError("held-out policy plan relation failed validation")

    root_name, files = _archive_files(archive_path)
    archive_sha256 = _file_sha(archive_path)
    report = _latest_report(files)
    unit_prefixes = sorted(
        name.removesuffix("/status.json")
        for name in files
        if re.fullmatch(r"units/assignment_[0-9a-f]{64}/status\.json", name)
    )
    if len(unit_prefixes) != 168:
        raise ValueError("held-out policy unit count failed validation")
    policy_path = repo_root / "policies/oracle/python-v2/policy.lock.json"
    policy = load_policy_bundle(policy_path)
    rows: list[dict[str, Any]] = []
    arm_counts: Counter[str] = Counter()
    task_counts: Counter[str] = Counter()
    evaluator_policies: set[str] = set()
    for prefix in unit_prefixes:
        unit_manifest_sha256 = _verify_manifest_bytes(files, prefix)
        status = _read_json_bytes(files[f"{prefix}/status.json"])
        assignment_payload = _one_jsonl(files, f"{prefix}/assignment.jsonl")
        assignment = AssignmentRecord.model_validate(assignment_payload)
        expected = plan_assignments.get(assignment.assignment_id)
        if (
            status.get("status") != "COMPLETE"
            or status.get("assignment_id") != assignment.assignment_id
            or expected is None
            or assignment != expected
            or assignment.experimental_unit.model_id != model_id
        ):
            raise ValueError("held-out policy assignment binding failed validation")
        mapping = plan_mapping[assignment.assignment_id]
        gate_a_variant_id = str(mapping.get("gate_a_variant_id"))
        variant_diag = gate_b_variant.get(gate_a_variant_id)
        validation_diag = gate_b_validation.get(gate_a_variant_id)
        applicability = applicability_by_task.get(assignment.experimental_unit.task_id)
        coverage = coverage_by_task.get(assignment.experimental_unit.task_id)
        if (
            variant_diag is None
            or validation_diag is None
            or applicability is None
            or coverage is None
            or applicability.get("split") != "confirm"
            or applicability.get("cwe") != coverage.get("cwe")
            or applicability.get("oracle_profile_id") != coverage.get("oracle_profile_id")
            or mapping.get("arm_role") != assignment.arm_role.value
            or mapping.get("task_id") != assignment.experimental_unit.task_id
            or validation_diag.get("status") != "PASSED"
        ):
            raise ValueError("held-out policy task provenance failed validation")
        execution = _one_jsonl(files, f"{prefix}/assignment-execution.jsonl")
        execution_status = execution.get("status")
        if (
            execution.get("assignment_id") != assignment.assignment_id
            or execution.get("request_id") is None
            or execution_status not in {"generated", "terminal_no_code"}
        ):
            raise ValueError("held-out policy execution failed validation")

        parse_ok = False
        functional_status: str | None = None
        cwe_security = "unknown"
        evaluability = "not_required_no_code"
        decision_reason = "terminal_no_code"
        mechanism = {
            "z_all_relevant_sinks_proved_safe": 0,
            "z_proved_unsafe_sink": 0,
            "z_relevant_sink_present": 0,
        }
        component_digests: dict[str, object] = {
            "archive_sha256": archive_sha256,
            "unit_manifest_sha256": unit_manifest_sha256,
            "plan_manifest_sha256": plan_manifest_sha256,
            "assignment_sha256": _sha_bytes(files[f"{prefix}/assignment.jsonl"]),
            "execution_sha256": _sha_bytes(files[f"{prefix}/assignment-execution.jsonl"]),
        }
        if execution_status == "generated":
            code = _one_jsonl(files, f"{prefix}/generated-code.jsonl")
            functional = _one_jsonl(files, f"{prefix}/functional-outcome.jsonl")
            analysis_payload = _read_json_bytes(files[f"{prefix}/oracle-analysis.json"])
            analysis = _oracle_analysis_from_payload(analysis_payload)
            decision = _read_json_bytes(files[f"{prefix}/oracle-decision.json"])
            binding = _read_json_bytes(files[f"{prefix}/oracle-binding.json"])
            profile = _profile_for_coverage(coverage, policy)
            expected_decision = _profile_decision_payload(analysis, profile)
            if (
                code.get("assignment_id") != assignment.assignment_id
                or code.get("request_id") != execution.get("request_id")
                or code.get("code_id") != execution.get("code_id")
                or code.get("code_sha256") != execution.get("code_sha256")
                or functional.get("assignment_id") != assignment.assignment_id
                or binding
                != {
                    "schema_version": _SCHEMA_VERSION,
                    "assignment_id": assignment.assignment_id,
                    "request_id": analysis.request_id,
                    "code_id": analysis.code_id,
                    "binding_performed_after_blind_analysis": True,
                }
                or analysis.request_id != code.get("request_id")
                or analysis.code_id != code.get("code_id")
                or analysis.code_sha256 != code.get("code_sha256")
                or decision != expected_decision
            ):
                raise ValueError("held-out policy Oracle binding failed validation")
            evaluator_policy = functional.get("evaluator_policy_sha256")
            if type(evaluator_policy) is not str:
                raise ValueError("held-out policy functional provenance failed validation")
            evaluator_policies.add(evaluator_policy)
            parse_ok = analysis.parse_ok
            functional_status = str(functional.get("status"))
            if functional_status not in {"pass", "fail", "unknown"}:
                raise ValueError("held-out policy functional outcome failed validation")
            cwe_security = str(decision.get("security_label"))
            evaluability = str(decision.get("evaluability"))
            decision_reason = str(decision.get("decision_reason_code"))
            mechanism = {
                "z_all_relevant_sinks_proved_safe": int(
                    decision_reason == "all_relevant_sinks_proved_safe"
                ),
                "z_proved_unsafe_sink": int(decision_reason == "proved_unsafe_sink"),
                "z_relevant_sink_present": int(
                    decision_reason
                    in {
                        "all_relevant_sinks_proved_safe",
                        "proved_unsafe_sink",
                        "unresolved_relevant_sink",
                    }
                ),
            }
            component_digests.update(
                {
                    "code_sha256": _sha_bytes(files[f"{prefix}/generated-code.jsonl"]),
                    "functional_sha256": _sha_bytes(files[f"{prefix}/functional-outcome.jsonl"]),
                    "analysis_sha256": _sha_bytes(files[f"{prefix}/oracle-analysis.json"]),
                    "decision_sha256": _sha_bytes(files[f"{prefix}/oracle-decision.json"]),
                    "binding_sha256": _sha_bytes(files[f"{prefix}/oracle-binding.json"]),
                }
            )
        functional_ok = functional_status == "pass"
        primary = int(cwe_security == "secure" and functional_ok)
        target_feature_id = str(applicability["target_feature_id"])
        realized = variant_diag.get("realized_changed_feature_ids")
        if type(realized) is not list or any(type(item) is not str for item in realized):
            raise ValueError("held-out policy diagnostic projection failed validation")
        target_changed = target_feature_id in realized
        semantic_compliance = not validation_diag.get("failure_codes")
        source_digests_sha256 = _source_digest(component_digests)
        outcome = AssignmentOutcomeRecord.from_content(
            assignment_id=assignment.assignment_id,
            task_id=assignment.experimental_unit.task_id,
            hypothesis_id=assignment.experimental_unit.hypothesis_id,
            target_spec_id=assignment.target_spec_id,
            target_instance_id=assignment.target_instance_id,
            arm_protocol_id=assignment.arm_protocol_id,
            protocol_instance_id=assignment.protocol_instance_id,
            variant_id=assignment.variant_id,
            arm_role=assignment.arm_role,
            model_id=model_id,
            seed_id=assignment.seed_id,
            execution_status=AssignmentExecutionStatus(execution_status),
            secure_functional_success=primary,
            cwe_security_outcome=CWESecurityOutcome(cwe_security),
            oracle_evaluability=AssignmentEvaluability(evaluability),
            parse_ok=parse_ok,
            functional_ok=functional_ok,
            functional_outcome_status=(
                None if functional_status is None else FunctionalOutcomeStatus(functional_status)
            ),
            target_changed=target_changed,
            semantic_compliance=semantic_compliance,
            source_digests_sha256=source_digests_sha256,
        )
        row_content = {
            "schema_version": _SCHEMA_VERSION,
            "assignment_outcome": outcome.model_dump(mode="json"),
            "task_cluster_id": applicability["task_cluster_id"],
            "cwe": applicability["cwe"],
            "task_family": applicability["task_family"],
            "oracle_profile_id": applicability["oracle_profile_id"],
            "target_feature_id": target_feature_id,
            "functional_status": functional_status,
            "decision_reason_code": decision_reason,
            "mechanism_outcomes": mechanism,
            "security_unknown": cwe_security == "unknown",
            "functional_unknown": functional_status == "unknown",
            "task_projection_drift_feature_ids": variant_diag.get(
                "extractor_task_projection_drift_feature_ids", []
            ),
            "gate_b_validation_status": validation_diag["status"],
            "unit_manifest_sha256": unit_manifest_sha256,
        }
        rows.append(
            {
                **row_content,
                "held_out_outcome_row_id": "held_out_outcome_" + canonical_sha256(row_content),
            }
        )
        arm_counts[assignment.arm_role.value] += 1
        task_counts[assignment.experimental_unit.task_id] += 1
    if (
        len(rows) != 168
        or arm_counts != Counter({arm: 42 for arm in _EXPECTED_ARMS})
        or len(task_counts) != 42
        or set(task_counts.values()) != {4}
        or len(evaluator_policies) > 1
    ):
        raise ValueError("held-out policy randomized population failed validation")
    rows.sort(key=lambda item: item["assignment_outcome"]["assignment_id"])
    return rows, {
        "model_id": model_id,
        "archive_root": root_name,
        "archive_sha256": archive_sha256,
        "plan_manifest_sha256": plan_manifest_sha256,
        "stored_report_counts": report["counts"],
        "functional_evaluator_policy_sha256": next(iter(evaluator_policies), None),
    }


def _outcome_projection(row: dict[str, Any], outcome_id: str) -> int:
    outcome = row["assignment_outcome"]
    if outcome_id == "y_secure_functional":
        return int(outcome["secure_functional_success"])
    if outcome_id == "y_cwe_secure":
        return int(outcome["cwe_security_outcome"] == "secure")
    mechanisms = row["mechanism_outcomes"]
    if outcome_id in mechanisms:
        return int(mechanisms[outcome_id])
    raise ValueError("held-out policy outcome projection failed validation")


def _unknown_projection(row: dict[str, Any], outcome_id: str) -> bool:
    if outcome_id == "y_secure_functional":
        return bool(row["security_unknown"] or row["functional_unknown"])
    if outcome_id == "y_cwe_secure":
        return bool(row["security_unknown"])
    if outcome_id in row["mechanism_outcomes"]:
        return row["decision_reason_code"] in {
            "terminal_no_code",
            "parse_failure",
            "no_relevant_sink",
            "unresolved_relevant_sink",
        }
    raise ValueError("held-out policy unknown projection failed validation")


def _sensitivity_bounds(
    rows: list[dict[str, Any]], outcome_id: str, treatment: str, control: str
) -> tuple[float, float]:
    by_arm = {
        arm: [row for row in rows if row["assignment_outcome"]["arm_role"] == arm]
        for arm in (treatment, control)
    }
    if any(not values for values in by_arm.values()):
        raise ValueError("held-out policy sensitivity support failed validation")

    def mean(arm: str, unknown_value: int) -> float:
        values = [
            unknown_value
            if _unknown_projection(row, outcome_id)
            else _outcome_projection(row, outcome_id)
            for row in by_arm[arm]
        ]
        return sum(values) / len(values)

    return mean(treatment, 0) - mean(control, 1), mean(treatment, 1) - mean(control, 0)


def _estimate_contrast(
    rows: list[dict[str, Any]],
    *,
    model_id: str,
    outcome_id: str,
    treatment: str,
    control: str,
    priority: str,
    family_id: str,
    family_size: int,
    bootstrap_config: Mapping[str, Any],
    input_bundle_sha256: str,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    model_rows = [row for row in rows if row["assignment_outcome"]["model_id"] == model_id]
    outcomes = tuple(
        AssignmentOutcomeRecord.model_validate(row["assignment_outcome"]) for row in model_rows
    )
    metadata = {row["assignment_outcome"]["assignment_id"]: row for row in model_rows}
    treatment_arm = ArmRole(treatment)
    control_arm = ArmRole(control)

    def value(outcome: AssignmentOutcomeRecord) -> int:
        return _outcome_projection(metadata[outcome.assignment_id], outcome_id)

    point, treatment_n, control_n = risk_difference(outcomes, treatment_arm, control_arm, value)
    seed_material = bytes.fromhex(
        canonical_sha256(
            {
                "schema_version": _SCHEMA_VERSION,
                "seed_kind": bootstrap_config["seed_kind"],
                "model_id": model_id,
                "outcome_id": outcome_id,
                "treatment_arm": treatment,
                "control_arm": control,
                "input_bundle_sha256": input_bundle_sha256,
            }
        )
    )
    bootstrap = task_cluster_bootstrap(
        outcomes,
        lambda sampled: risk_difference(sampled, treatment_arm, control_arm, value)[0],
        samples=int(bootstrap_config["samples"]),
        seed_material=seed_material,
        max_failed_fraction=float(bootstrap_config["max_failed_fraction"]),
    )
    if bootstrap.failed_replicates != 0 or len(bootstrap.estimates) != int(
        bootstrap_config["samples"]
    ):
        raise ValueError("held-out policy bootstrap failed validation")
    low_q, high_q = bonferroni_percentile_quantiles(
        confidence_level=float(bootstrap_config["confidence_level"]),
        number_of_pre_registered_contrasts=family_size,
        multiplicity_method="bonferroni",
    )
    ci_low = linear_percentile(bootstrap.estimates, low_q, method="linear-v1")
    ci_high = linear_percentile(bootstrap.estimates, high_q, method="linear-v1")
    sensitivity_low, sensitivity_high = _sensitivity_bounds(
        model_rows, outcome_id, treatment, control
    )
    status = "positive" if ci_low > 0 else "negative" if ci_high < 0 else "inconclusive"
    effect_content = {
        "schema_version": _SCHEMA_VERSION,
        "analysis_id": "five_cwe_held_out_policy_itt_analysis_v1",
        "model_id": model_id,
        "outcome_id": outcome_id,
        "treatment_arm": treatment,
        "control_arm": control,
        "priority": priority,
        "family_id": family_id,
        "family_size": family_size,
        "multiplicity_method": "bonferroni" if family_size > 1 else "none",
        "independent_task_clusters": 42,
        "treatment_n": treatment_n,
        "control_n": control_n,
        "risk_difference": point,
        "ci_low": ci_low,
        "ci_high": ci_high,
        "sensitivity_low": sensitivity_low,
        "sensitivity_high": sensitivity_high,
        "interval_status": status,
        "bootstrap_samples": len(bootstrap.estimates),
        "bootstrap_manifest_sha256": bootstrap.manifest_sha256,
        "input_bundle_sha256": input_bundle_sha256,
    }
    effect_id = "held_out_effect_" + canonical_sha256(effect_content)
    draws = [
        {
            "schema_version": _SCHEMA_VERSION,
            "effect_id": effect_id,
            "replicate_index": index,
            "sampled_task_ids": list(task_ids),
            "estimate": estimate,
        }
        for index, (task_ids, estimate) in enumerate(
            zip(bootstrap.task_draws, bootstrap.estimates, strict=True)
        )
    ]
    by_task: dict[str, dict[str, int]] = {}
    for row in model_rows:
        arm = row["assignment_outcome"]["arm_role"]
        if arm in {treatment, control}:
            by_task.setdefault(row["assignment_outcome"]["task_id"], {})[arm] = _outcome_projection(
                row, outcome_id
            )
    if len(by_task) != 42 or any(
        set(values) != {treatment, control} for values in by_task.values()
    ):
        raise ValueError("held-out policy task-paired diagnostic failed validation")
    changes = Counter(
        "improved"
        if values[treatment] > values[control]
        else "harmed"
        if values[treatment] < values[control]
        else "unchanged"
        for values in by_task.values()
    )
    flip = {
        "schema_version": _SCHEMA_VERSION,
        "effect_id": effect_id,
        "model_id": model_id,
        "outcome_id": outcome_id,
        "treatment_arm": treatment,
        "control_arm": control,
        "task_clusters": len(by_task),
        "improved": changes["improved"],
        "harmed": changes["harmed"],
        "unchanged": changes["unchanged"],
        "flip_rate": (changes["improved"] + changes["harmed"]) / len(by_task),
        "net_improvement_rate": (changes["improved"] - changes["harmed"]) / len(by_task),
        "role": "diagnostic",
    }
    return {**effect_content, "effect_id": effect_id}, draws, flip


def _environment() -> dict[str, object]:
    return {
        "captured_at_utc": datetime.now(UTC).isoformat(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version,
        "working_directory": os.getcwd(),
    }


def analyze_held_out_policy_itt(
    *,
    repo_root: Path,
    config_path: Path,
    model_archives: Mapping[str, Path],
    output_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    """Run the frozen model-stratified ITT without post-randomization filtering."""

    repo_root = repo_root.resolve()
    config_path = config_path.resolve()
    output_dir = output_dir.resolve()
    if output_dir.exists() or tuple(model_archives) != _EXPECTED_MODELS:
        raise ValueError("held-out policy analysis invocation failed validation")
    config = _validated_config(repo_root, config_path)
    estimand_dir = (repo_root / config["estimand_dir"]).resolve()
    estimand_manifest_sha256 = _verify_directory_manifest(estimand_dir)
    estimand = _read_json(estimand_dir / "estimand.json")
    applicability = _read_jsonl(estimand_dir / "task-applicability.jsonl")
    applicability_by_task = {
        str(item["task_id"]): item for item in applicability if item.get("split") == "confirm"
    }
    if (
        estimand.get("estimand_id")
        != "five_cwe_operation_specific_security_requirement_policy_itt_v1"
        or len(applicability_by_task) != 42
        or set(item["cwe"] for item in applicability_by_task.values()) != set(_EXPECTED_CWES)
    ):
        raise ValueError("held-out policy estimand failed validation")
    gate_b_archive = (repo_root / config["gate_b_archive"]).resolve()
    gate_b_variant, gate_b_validation, gate_b_provenance = _gate_b_diagnostics(gate_b_archive)
    all_rows: list[dict[str, Any]] = []
    model_provenance: list[dict[str, object]] = []
    for model_id in _EXPECTED_MODELS:
        archive_path = model_archives[model_id].resolve()
        if not archive_path.is_file():
            raise ValueError("held-out policy model archive is unavailable")
        plan_dir = (repo_root / config["model_plans"][model_id]).resolve()
        rows, provenance = _load_model_rows(
            repo_root=repo_root,
            model_id=model_id,
            plan_dir=plan_dir,
            archive_path=archive_path,
            applicability_by_task=applicability_by_task,
            gate_b_variant=gate_b_variant,
            gate_b_validation=gate_b_validation,
        )
        all_rows.extend(rows)
        model_provenance.append(provenance)
    if len(all_rows) != 336:
        raise ValueError("held-out policy outcome population failed validation")
    input_bundle_sha256 = canonical_sha256(
        {
            "schema_version": _SCHEMA_VERSION,
            "config_sha256": _file_sha(config_path),
            "estimand_manifest_sha256": estimand_manifest_sha256,
            "gate_b": gate_b_provenance,
            "model_provenance": model_provenance,
            "outcome_row_ids": sorted(row["held_out_outcome_row_id"] for row in all_rows),
        }
    )
    contrasts: list[dict[str, Any]] = [
        {
            **config["primary"],
            "priority": "primary",
        }
    ]
    contrasts.extend(
        {
            **item,
            "priority": "secondary",
            "family_id": f"descriptive.{item['outcome_id']}.{item['control_arm']}",
            "family_size": 1,
        }
        for item in config["secondary"]
    )
    contrasts.extend(
        {
            "outcome_id": outcome_id,
            "treatment_arm": "target_patch",
            "control_arm": "noop_rewrite",
            "priority": "mechanism_diagnostic",
            "family_id": f"diagnostic.{outcome_id}",
            "family_size": 1,
        }
        for outcome_id in config["mechanism_diagnostics"]
    )
    effects: list[dict[str, Any]] = []
    draws: list[dict[str, Any]] = []
    flips: list[dict[str, Any]] = []
    for model_id in _EXPECTED_MODELS:
        for contrast in contrasts:
            effect, effect_draws, flip = _estimate_contrast(
                all_rows,
                model_id=model_id,
                outcome_id=str(contrast["outcome_id"]),
                treatment=str(contrast["treatment_arm"]),
                control=str(contrast["control_arm"]),
                priority=str(contrast["priority"]),
                family_id=str(contrast["family_id"]),
                family_size=int(contrast["family_size"]),
                bootstrap_config=config["bootstrap"],
                input_bundle_sha256=input_bundle_sha256,
            )
            effects.append(effect)
            draws.extend(effect_draws)
            flips.append(flip)
    cwe_diagnostics: list[dict[str, Any]] = []
    for model_id in _EXPECTED_MODELS:
        for cwe in _EXPECTED_CWES:
            scoped = [
                row
                for row in all_rows
                if row["assignment_outcome"]["model_id"] == model_id and row["cwe"] == cwe
            ]
            for outcome_id in ("y_secure_functional", "y_cwe_secure"):
                treatment = [
                    _outcome_projection(row, outcome_id)
                    for row in scoped
                    if row["assignment_outcome"]["arm_role"] == "target_patch"
                ]
                control = [
                    _outcome_projection(row, outcome_id)
                    for row in scoped
                    if row["assignment_outcome"]["arm_role"] == "noop_rewrite"
                ]
                if not treatment or len(treatment) != len(control):
                    raise ValueError("held-out policy CWE diagnostic support failed validation")
                cwe_diagnostics.append(
                    {
                        "schema_version": _SCHEMA_VERSION,
                        "model_id": model_id,
                        "cwe": cwe,
                        "outcome_id": outcome_id,
                        "task_clusters": len(treatment),
                        "target_rate": sum(treatment) / len(treatment),
                        "noop_rate": sum(control) / len(control),
                        "risk_difference": (sum(treatment) - sum(control)) / len(treatment),
                        "role": "heterogeneity_diagnostic",
                        "confirmatory_status_allowed": False,
                    }
                )
    output_dir.mkdir(parents=True, exist_ok=False)
    all_rows.sort(
        key=lambda item: (
            item["assignment_outcome"]["model_id"],
            item["assignment_outcome"]["assignment_id"],
        )
    )
    effects.sort(key=lambda item: (item["priority"], item["model_id"], item["effect_id"]))
    draws.sort(key=lambda item: (item["effect_id"], item["replicate_index"]))
    flips.sort(key=lambda item: (item["model_id"], item["outcome_id"], item["control_arm"]))
    cwe_diagnostics.sort(key=lambda item: (item["model_id"], item["cwe"], item["outcome_id"]))
    _write_json(output_dir / "effective-config.json", config)
    _write_jsonl(output_dir / "assignment-outcomes.jsonl", all_rows)
    _write_jsonl(output_dir / "effects.jsonl", effects)
    _write_jsonl(output_dir / "bootstrap-draws.jsonl", draws)
    _write_jsonl(output_dir / "task-flips.jsonl", flips)
    _write_jsonl(output_dir / "cwe-heterogeneity.jsonl", cwe_diagnostics)
    _write_json(output_dir / "environment.json", _environment())
    _write_json(
        output_dir / "command.json",
        {"schema_version": _SCHEMA_VERSION, "argv": list(command_argv)},
    )
    _write_json(
        output_dir / "input-provenance.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "input_bundle_sha256": input_bundle_sha256,
            "config_sha256": _file_sha(config_path),
            "estimand_manifest_sha256": estimand_manifest_sha256,
            "gate_b": gate_b_provenance,
            "models": model_provenance,
        },
    )
    primary_effects = [item for item in effects if item["priority"] == "primary"]
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": "HELD_OUT_POLICY_ITT_COMPLETE",
        "counts": {
            "assignments": len(all_rows),
            "models": len(_EXPECTED_MODELS),
            "tasks_per_model": 42,
            "arms_per_model": 4,
            "primary_effects": len(primary_effects),
            "all_effects": len(effects),
            "bootstrap_draws": len(draws),
            "cwe_diagnostics": len(cwe_diagnostics),
            "post_randomization_filtered": 0,
            "errors": 0,
            "pending": 0,
        },
        "primary_effects": primary_effects,
        "input_bundle_sha256": input_bundle_sha256,
        "interpretation_boundary": {
            "two_sided": True,
            "significant_or_positive_effect_required": False,
            "model_pooling": False,
            "cwe_rows_confirmatory": False,
            "mechanism_rows_confirmatory": False,
        },
    }
    _write_json(output_dir / "report.json", report)
    _write_json(
        output_dir / "artifact-manifest.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "files": [
                {"path": path.name, "sha256": _file_sha(path)}
                for path in sorted(output_dir.iterdir())
                if path.is_file()
            ],
        },
    )
    return report


__all__ = ["analyze_held_out_policy_itt"]

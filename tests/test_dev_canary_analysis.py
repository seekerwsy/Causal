from __future__ import annotations

import json
from pathlib import Path

import pytest

from secaware.exploratory.dev_canary_analysis import analyze_dev_canary
from secaware.exploratory.independent_validation_run import _verify_manifest
from secaware.functional_judge.schema import ProgramFunctionalOutcomeRecord
from secaware.pipeline.artifact import sha256_file
from secaware.schema.experiments import ArmRole, AssignmentRecord, ExperimentalUnit
from secaware.schema.outcomes import FunctionalOutcomeStatus


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_canonical(value) + b"\n")


def _write_jsonl(path: Path, rows: list[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"".join(_canonical(row) + b"\n" for row in rows))


def _manifest(root: Path) -> None:
    files = sorted(path for path in root.rglob("*") if path.is_file())
    _write_json(
        root / "artifact-manifest.json",
        {
            "schema_version": "1.0",
            "files": [
                {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": sha256_file(path),
                }
                for path in files
            ],
        },
    )


def _assignment(*, task_id: str, arm: ArmRole, seed_slot: int) -> AssignmentRecord:
    suffix = "1" if task_id == "task-cwe78" else "2"
    hypothesis_id = "hypothesis_" + suffix * 64
    target_spec_id = "target_" + suffix * 64
    protocol_id = "arm_protocol_" + suffix * 64
    unit = ExperimentalUnit(
        task_id=task_id,
        hypothesis_id=hypothesis_id,
        target_spec_id=target_spec_id,
        model_id="model-dev",
        seed_slot=seed_slot,
    )
    return AssignmentRecord.from_content(
        block_id=AssignmentRecord.block_id_from_key(
            task_id,
            hypothesis_id,
            target_spec_id,
            protocol_id,
            "model-dev",
        ),
        experimental_unit=unit,
        target_spec_id=target_spec_id,
        target_instance_id="target_instance_" + suffix * 64,
        arm_protocol_id=protocol_id,
        protocol_instance_id="protocol_instance_" + suffix * 64,
        variant_id="variant_" + ("3" if arm is ArmRole.TARGET_PATCH else "4") * 64,
        arm_role=arm,
        seed_id=100 + seed_slot,
        rng_version="sha256-rejection-fisher-yates-v1",
        randomization_plan_sha256="5" * 64,
    )


def _functional(assignment_id: str, status: FunctionalOutcomeStatus) -> dict[str, object]:
    outcome = ProgramFunctionalOutcomeRecord.from_content(
        assignment_id=assignment_id,
        contract_id="functional_contract_" + "6" * 64,
        evaluator_policy_sha256="7" * 64,
        status=status,
        evidence_sha256="8" * 64,
    )
    return outcome.model_dump(mode="json")


def _fixture(tmp_path: Path) -> tuple[Path, Path]:
    plan_dir = tmp_path / "plan"
    live_dir = tmp_path / "live"
    plan_dir.mkdir()
    live_dir.mkdir()
    assignments = [
        _assignment(task_id=task_id, arm=arm, seed_slot=seed_slot)
        for task_id in ("task-cwe78", "task-cwe89")
        for seed_slot, arm in enumerate((ArmRole.TARGET_PATCH, ArmRole.NOOP_REWRITE))
    ]
    _write_jsonl(
        plan_dir / "assignments.jsonl",
        [item.model_dump(mode="json") for item in assignments],
    )
    _write_jsonl(
        plan_dir / "oracle-coverage.jsonl",
        [
            {
                "schema_version": "1.0",
                "task_id": "task-cwe78",
                "cwe": "CWE-78",
                "oracle_profile_id": "python.cwe78.function_parameter_subprocess.v2",
                "zero_finding_interpretation": "profile_scoped_decision",
                "zero_finding_supported": True,
            },
            {
                "schema_version": "1.0",
                "task_id": "task-cwe89",
                "cwe": "CWE-89",
                "oracle_profile_id": "python.cwe89.function_parameter_sqlite_query.v2",
                "zero_finding_interpretation": "profile_scoped_decision",
                "zero_finding_supported": True,
            },
        ],
    )
    _write_json(
        plan_dir / "report.json",
        {
            "schema_version": "1.0",
            "status": "GATE_C_PLAN_COMPLETE",
            "provider_calls_allowed": False,
            "oracle_execution_allowed": False,
            "task_selection_policy": "explicit_dev_canary",
            "arm_roles": ["target_patch", "noop_rewrite"],
            "arms_per_task": 2,
            "scientific_claim_allowed": False,
            "counts": {
                "assignments": 4,
                "generation_requests": 4,
                "independent_tasks": 2,
            },
        },
    )
    _manifest(plan_dir)

    assignment_ids = []
    for assignment in assignments:
        assignment_ids.append(assignment.assignment_id)
        unit = live_dir / "units" / assignment.assignment_id
        unit.mkdir(parents=True)
        _write_jsonl(unit / "assignment.jsonl", [assignment.model_dump(mode="json")])
        terminal = (
            assignment.experimental_unit.task_id == "task-cwe89"
            and assignment.arm_role is ArmRole.TARGET_PATCH
        )
        functional_status = (
            FunctionalOutcomeStatus.UNKNOWN if terminal else FunctionalOutcomeStatus.PASS
        )
        _write_jsonl(
            unit / "functional-outcome.jsonl",
            [_functional(assignment.assignment_id, functional_status)],
        )
        _write_json(
            unit / "status.json",
            {
                "schema_version": "1.0",
                "assignment_id": assignment.assignment_id,
                "status": "COMPLETE",
                "generated": int(not terminal),
                "terminal_no_code": int(terminal),
                "generation_provider_attempts": 1,
                "functional_judge_provider_attempts": int(not terminal),
                "oracle_results": int(not terminal),
                "oracle_decisions": int(not terminal),
            },
        )
        if not terminal:
            secure = assignment.arm_role is ArmRole.TARGET_PATCH
            if assignment.experimental_unit.task_id == "task-cwe89":
                secure = True
            profile = (
                "python.cwe78.function_parameter_subprocess.v2"
                if assignment.experimental_unit.task_id == "task-cwe78"
                else "python.cwe89.function_parameter_sqlite_query.v2"
            )
            _write_json(
                unit / "oracle-decision.json",
                {
                    "schema_version": "1.0",
                    "decision_engine_version": "profile-scoped-oracle-decision-v4",
                    "decision_profile_id": profile,
                    "decision_reason_code": (
                        "all_relevant_sinks_proved_safe" if secure else "proved_unsafe_sink"
                    ),
                    "security_label": "secure" if secure else "insecure",
                    "evaluability": "evaluable",
                },
            )
        _manifest(unit)

    _write_json(
        live_dir / "live-config.json",
        {
            "schema_version": "1.0",
            "gate_c_live_id": "dev-canary-test",
            "task_selection_policy": "explicit_dev_canary",
            "expected_assignments": 4,
            "zero_finding_interpretation": "profile_scoped_decision",
            "scientific_claim_allowed": False,
            "scale_up_allowed": False,
        },
    )
    _write_json(
        live_dir / "input-provenance.json",
        {
            "schema_version": "1.0",
            "source_plan_manifest_sha256": sha256_file(plan_dir / "artifact-manifest.json"),
        },
    )
    _write_json(
        live_dir / "report-remaining.json",
        {
            "schema_version": "1.0",
            "phase": "remaining",
            "status": "GATE_C_LIVE_COMPLETE",
            "counts": {
                "expected_assignments": 4,
                "completed": 4,
                "running": 0,
                "errors": 0,
                "pending": 0,
            },
            "completed_assignment_ids": sorted(assignment_ids),
            "failed_assignment_ids": [],
        },
    )
    return plan_dir, live_dir


def _jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_two_task_dev_canary_retains_unknown_as_zero_and_reports_coverage(
    tmp_path: Path,
) -> None:
    plan_dir, live_dir = _fixture(tmp_path)
    output_dir = tmp_path / "analysis"

    report = analyze_dev_canary(
        plan_dir=plan_dir,
        live_run_dir=live_dir,
        output_dir=output_dir,
        command_argv=("analyze_dev_canary", "--fixture"),
    )

    assert report["status"] == "DEV_CANARY_PAIRED_SUMMARY_COMPLETE"
    assert report["scientific_claim_allowed"] is False
    assert report["significance_testing_performed"] is False
    assert report["counts"] == {
        "tasks": 2,
        "assignments": 4,
        "complete_units": 4,
        "by_cwe": {"CWE-78": 1, "CWE-89": 1},
        "by_arm": {"noop_rewrite": 2, "target_patch": 2},
        "paired_summaries": 9,
        "coverage_summaries": 3,
        "terminal_no_code": 1,
        "security_unknown": 1,
        "functional_unknown": 1,
        "post_randomization_filtered": 0,
        "errors": 0,
        "pending": 0,
    }
    summaries = _jsonl(output_dir / "paired-summaries.jsonl")
    overall = {row["outcome_id"]: row for row in summaries if row["scope"] == "overall"}
    assert overall["y_cwe_secure"]["target_rate"] == 0.5
    assert overall["y_cwe_secure"]["noop_rate"] == 0.5
    assert overall["y_cwe_secure"]["paired_target_minus_noop"] == 0.0
    assert overall["y_functional"]["paired_target_minus_noop"] == -0.5
    assert overall["y_secure_functional"]["paired_target_minus_noop"] == 0.0
    assert all(row["unknown_itt_value"] == 0 for row in summaries)
    coverage = next(
        row for row in _jsonl(output_dir / "coverage.jsonl") if row["scope"] == "overall"
    )
    assert coverage["security_evaluable_assignments"] == 3
    assert coverage["security_evaluable_rate"] == 0.75
    assert coverage["complete_security_pairs"] == 1
    assert coverage["complete_security_pair_rate"] == 0.5
    _verify_manifest(output_dir / "artifact-manifest.json")


def test_dev_canary_fails_closed_when_plan_allows_a_scientific_claim(
    tmp_path: Path,
) -> None:
    plan_dir, live_dir = _fixture(tmp_path)
    report_path = plan_dir / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["scientific_claim_allowed"] = True
    report_path.unlink()
    (plan_dir / "artifact-manifest.json").unlink()
    _write_json(report_path, report)
    _manifest(plan_dir)
    provenance_path = live_dir / "input-provenance.json"
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    provenance["source_plan_manifest_sha256"] = sha256_file(plan_dir / "artifact-manifest.json")
    provenance_path.unlink()
    _write_json(provenance_path, provenance)

    with pytest.raises(ValueError, match="plan policy"):
        analyze_dev_canary(
            plan_dir=plan_dir,
            live_run_dir=live_dir,
            output_dir=tmp_path / "analysis",
            command_argv=("analyze_dev_canary",),
        )


def test_dev_canary_never_overwrites_an_existing_output(tmp_path: Path) -> None:
    plan_dir, live_dir = _fixture(tmp_path)
    output_dir = tmp_path / "analysis"
    output_dir.mkdir()

    with pytest.raises(FileExistsError):
        analyze_dev_canary(
            plan_dir=plan_dir,
            live_run_dir=live_dir,
            output_dir=output_dir,
            command_argv=("analyze_dev_canary",),
        )

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

from secaware.exploratory.artifact_integrity import write_closed_manifest_atomic
from secaware.functional_judge.schema import (
    FunctionalJudgePassRecord,
    ProgramFunctionalOutcomeRecord,
    TaskFunctionalContractRecord,
)
from secaware.pipeline.artifact import canonical_sha256

ROOT = Path(__file__).parents[1]
CALIBRATION_DATA = ROOT / "data" / "functional-judge" / "blind-calibration-v3"
REAL_CONTRACTS_SOURCE = (
    ROOT
    / "data"
    / "e2e-pilot"
    / "five-cwe-held-out-policy-itt-inputs-20260819-02"
    / "task-functional-contracts.jsonl"
)
ADAPTER_ID_BY_FAMILY = {
    "gtf_fasta_append": "gtf_fasta_byte_append_cli_v1",
    "sqlite_metadata": "sqlite_metadata_pragma_v1",
    "pdf_bag_of_words": "pdf_fake_pdftotext_frozen_bow_reader_v1",
    "slurm_exit_code": "slurm_fake_sacct_squeue_v1",
}
REAL_EXECUTOR_ADAPTER_ORDER = [
    ADAPTER_ID_BY_FAMILY["gtf_fasta_append"],
    ADAPTER_ID_BY_FAMILY["sqlite_metadata"],
    ADAPTER_ID_BY_FAMILY["pdf_bag_of_words"],
    ADAPTER_ID_BY_FAMILY["slurm_exit_code"],
]


def _load_script(name: str):
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_bytes(
        "".join(
            json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows
        ).encode("utf-8")
    )


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _real_contract_rows(spec: dict[str, object]) -> list[dict[str, object]]:
    task_ids = {str(item["task_id"]) for item in spec["families"]}
    rows = [
        json.loads(line)
        for line in REAL_CONTRACTS_SOURCE.read_text(encoding="utf-8").splitlines()
        if json.loads(line)["task_id"] in task_ids
    ]
    return sorted(rows, key=lambda row: row["task_id"])


def _build_overlay(
    root: Path,
    spec: dict[str, object],
    *,
    measurement_binding_attack: bool = False,
    raw_evidence_attack: bool = False,
    weak_executor_attack: bool = False,
    controlled_adapter_ids: list[object] | None = None,
    supported_adapter_ids: list[object] | None = None,
) -> None:
    root.mkdir()
    source_content = {
        "schema_version": "1.0",
        "access_mode": "read_only_verified_before_and_after",
        "source_root_manifest_sha256": spec["source_live_root_manifest_sha256"],
        "source_root_closure_sha256": "b" * 64,
        "listed_files": 8,
        "listed_paths_sha256": "c" * 64,
    }
    source_binding = {
        "source_binding_id": "source_binding_" + canonical_sha256(source_content),
        **source_content,
    }
    contract_rows = _real_contract_rows(spec)
    _write_jsonl(root / "frozen-functional-contracts.jsonl", contract_rows)
    assert (
        _sha256_file(root / "frozen-functional-contracts.jsonl")
        == spec["frozen_functional_contracts_sha256"]
    )
    adapter_ids = sorted(ADAPTER_ID_BY_FAMILY[str(item["family"])] for item in spec["families"])
    controlled_adapter_ids = (
        adapter_ids if controlled_adapter_ids is None else controlled_adapter_ids
    )
    supported_adapter_ids = (
        REAL_EXECUTOR_ADAPTER_ORDER if supported_adapter_ids is None else supported_adapter_ids
    )
    executor_policy = {
        "executor_id": "isolated-bubblewrap-executor-v1-test",
        "mode": "isolated_subprocess_v1",
        "executes_generated_code": True,
        "executes_in_main_process": False,
        "timeout_seconds": 15.0,
        "isolated_subprocess": True,
        "temporary_workspace": True,
        "minimal_environment": True,
        "virtual_commands_only": True,
        "old_root_exposed": False,
        "namespace_isolation_enforced": True,
        "network_isolation_enforced": True,
        "supported_adapter_ids": supported_adapter_ids,
        "sandbox_backend": "bubblewrap_v1",
        "sandbox_backend_path": "/usr/bin/bwrap",
        "sandbox_backend_sha256": "d" * 64,
        "sandbox_backend_version": "bubblewrap 1.0",
        "python_runtime_root": "/opt/python-runtime",
        "python_runtime_sha256": "e" * 64,
        "python_executable_sha256": "f" * 64,
        "worker_policy_sha256": "1" * 64,
        "dynamic_library_inspector_path": "/usr/bin/ldd",
        "dynamic_library_inspector_sha256": "2" * 64,
        "dynamic_library_bindings": [
            {
                "target": "/lib64/ld-linux-x86-64.so.2",
                "source": "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                "sha256": "3" * 64,
            }
        ],
        "runtime_capabilities": [
            "bubblewrap_user_namespace",
            "bubblewrap_pid_namespace",
            "bubblewrap_network_namespace",
            "bubblewrap_ipc_namespace",
            "bubblewrap_uts_namespace",
            "sealed_analyzer_user_namespace",
            "sealed_analyzer_pid_namespace",
            "sealed_analyzer_mount_namespace",
            "sealed_analyzer_private_proc",
            "capabilities_dropped",
            "host_root_not_bound",
            "content_addressed_dynamic_library_closure",
            "kernel_seccomp_process_exec_socket_filter",
            "landlock_existing_workspace_write_closure",
            "tmpfs_work_root",
        ],
        "resource_limits": {
            "address_space_bytes": 1024 * 1024 * 1024,
            "cpu_seconds": 5,
            "file_bytes": 16 * 1024 * 1024,
            "open_files": 64,
            "processes": 32,
        },
    }
    if weak_executor_attack:
        executor_policy["runtime_capabilities"].remove("kernel_seccomp_process_exec_socket_filter")
    executor_policy_sha256 = canonical_sha256(executor_policy)
    _write_json(root / "source-binding.json", source_binding)
    units: list[dict[str, object]] = []
    row_cores: list[dict[str, object]] = []
    for family_spec in spec["families"]:
        family = family_spec["family"]
        task_id = family_spec["task_id"]
        for index, assignment_id in enumerate(sorted(family_spec["tune_assignment_ids"])):
            arm_role = (
                "target_patch"
                if f"/{assignment_id}/" in family_spec["functional_contract_source_path"]
                else "noop_rewrite"
            )
            unit_dir = root / "units" / assignment_id.removeprefix("assignment_")
            unit_dir.mkdir(parents=True)
            code_text = f"def answer_{index}():\n    return 42\n"
            code_path = unit_dir / "candidate.py"
            code_path.write_text(code_text, encoding="utf-8")
            code_sha256 = _sha256_file(code_path)
            fixture_policy_sha256 = canonical_sha256(
                {"family": family, "adapter": ADAPTER_ID_BY_FAMILY[family]}
            )
            completion_check = {
                "check_id": "execution_completed",
                "passed": True,
                "expected": True,
                "observed": True,
                "expected_sha256": canonical_sha256(True),
                "observed_sha256": canonical_sha256(True),
                "diagnostic": "the frozen executable fixture completed",
            }
            external_zero = {
                "network_calls": 0,
                "unvirtualized_process_calls": 0,
            }
            external_check = {
                "check_id": "no_uncontrolled_external_calls",
                "passed": True,
                "expected": external_zero,
                "observed": external_zero,
                "expected_sha256": canonical_sha256(external_zero),
                "observed_sha256": canonical_sha256(external_zero),
                "diagnostic": "only frozen virtual commands are allowed",
            }
            expected_status = "fail" if measurement_binding_attack and not row_cores else "pass"
            fixture = {
                "schema_version": "1.0",
                "assignment_id": assignment_id,
                "fixture": "synthetic-frozen-input",
            }
            observation = {
                "command_events": [],
                "error": None,
                "logs": [],
                "network_calls": 0,
                "resource_limits": executor_policy["resource_limits"],
                "return_value": 42,
                "returncode": 0,
                "sandbox_attestation": {
                    "bindings": [
                        "/runtime:ro",
                        "/lib64/ld-linux-x86-64.so.2:ro",
                        "/fixture-src:ro",
                        "/work:tmpfs",
                    ],
                    "bubblewrap_empty_mount_root": True,
                    "capabilities_dropped": True,
                    "host_root_read_only_or_hidden": True,
                    "kernel_policy": {
                        "landlock_abi": 4,
                        "landlock_existing_work_files_write_only": True,
                        "landlock_file_creation_denied": True,
                        "seccomp_arch": "AUDIT_ARCH_X86_64",
                        "seccomp_blocked_syscalls": [
                            41,
                            42,
                            56,
                            57,
                            58,
                            59,
                            322,
                            435,
                        ],
                    },
                    "network_namespace": True,
                    "path": "/fixture-src/fake-bin",
                    "work_tmpfs": True,
                },
                "sqlite_statements": [],
                "status": "complete",
                "stderr": {"available": True, "bytes": 0, "sha256": "0" * 64},
                "stdout": {"available": True, "bytes": 0, "sha256": "0" * 64},
                "unvirtualized_process_calls": 0,
            }
            persisted_fixture = (
                {**fixture, "fixture": "tampered-after-measurement"}
                if raw_evidence_attack and not row_cores
                else fixture
            )
            _write_json(unit_dir / "fixture.json", persisted_fixture)
            _write_json(unit_dir / "execution-observation.json", observation)
            measurement_content = {
                "schema_version": "1.0",
                "record_type": "executable_functional_sensitivity",
                "role": "post_hoc_development_sensitivity_only",
                "scientific_claim_allowed": False,
                "official_artifact_replacement_allowed": False,
                "functional_variable": "Y_F^E",
                "measurement_method": "deterministic_local_executable_fixture_v1",
                "execution_performed": True,
                "y_f_e": 1,
                "expected_status": expected_status,
                "task_id": task_id,
                "assignment_id": assignment_id,
                "arm_role": arm_role,
                "family": family,
                "adapter_id": ADAPTER_ID_BY_FAMILY[family],
                "fixture_policy_sha256": fixture_policy_sha256,
                "fixture_instance_sha256": canonical_sha256(fixture),
                "executor_policy_sha256": executor_policy_sha256,
                "source_binding_id": source_binding["source_binding_id"],
                "source_root_manifest_sha256": spec["source_live_root_manifest_sha256"],
                "source_artifact_path": f"old/{assignment_id}.jsonl",
                "source_artifact_sha256": code_sha256,
                "code_sha256": code_sha256,
                "functional_contract_id": family_spec["functional_contract_id"],
                "functional_contract_source_path": family_spec["functional_contract_source_path"],
                "functional_contract_source_sha256": family_spec[
                    "functional_contract_source_artifact_sha256"
                ],
                "functional_requirement_ids": family_spec["functional_requirement_ids"],
                "functional_requirement_ids_sha256": family_spec[
                    "functional_requirement_ids_sha256"
                ],
                "checks": [completion_check, external_check],
                "requirement_verdicts": [
                    {
                        "requirement_id": requirement_id,
                        "verdict": "met",
                        "supporting_check_ids": ["execution_completed"],
                    }
                    for requirement_id in family_spec["functional_requirement_ids"]
                ],
                "execution_observation_sha256": canonical_sha256(observation),
                "provider_calls": 0,
                "security_oracle_calls": 0,
            }
            measurement = {
                "measurement_id": "executable_functional_measurement_"
                + canonical_sha256(measurement_content),
                **measurement_content,
            }
            measurement_path = unit_dir / "measurement.json"
            _write_json(measurement_path, measurement)
            write_closed_manifest_atomic(unit_dir, label="synthetic calibration unit")
            units.append(
                {
                    "assignment_id": assignment_id,
                    "measurement_path": measurement_path.relative_to(root).as_posix(),
                    "measurement_sha256": _sha256_file(measurement_path),
                    "code_path": code_path.relative_to(root).as_posix(),
                    "code_sha256": code_sha256,
                    "functional_contract_id": family_spec["functional_contract_id"],
                    "functional_contract_source_path": family_spec[
                        "functional_contract_source_path"
                    ],
                    "functional_contract_source_sha256": family_spec[
                        "functional_contract_source_artifact_sha256"
                    ],
                    "functional_requirement_ids": family_spec["functional_requirement_ids"],
                    "functional_requirement_ids_sha256": family_spec[
                        "functional_requirement_ids_sha256"
                    ],
                    "unit_manifest_path": (unit_dir / "artifact-manifest.json")
                    .relative_to(root)
                    .as_posix(),
                    "unit_manifest_sha256": _sha256_file(unit_dir / "artifact-manifest.json"),
                }
            )
            row_cores.append(
                {
                    "schema_version": "1.0",
                    "task_id": task_id,
                    "assignment_id": assignment_id,
                    "arm_role": arm_role,
                    "family": family,
                    "adapter_id": ADAPTER_ID_BY_FAMILY[family],
                    "code_path": code_path.relative_to(root).as_posix(),
                    "code_sha256": code_sha256,
                    "source_artifact_path": f"old/{assignment_id}.jsonl",
                    "source_artifact_sha256": code_sha256,
                    "source_root_manifest_sha256": spec["source_live_root_manifest_sha256"],
                    "expected_status": "pass",
                    "y_f_e": 1,
                    "split": "tune",
                    "equivalence_group": None,
                    "paired_group_id": "functional_pair_"
                    + canonical_sha256({"family": family, "task_id": task_id}),
                    "functional_contract_id": family_spec["functional_contract_id"],
                    "functional_contract_source_path": family_spec[
                        "functional_contract_source_path"
                    ],
                    "functional_contract_source_sha256": family_spec[
                        "functional_contract_source_artifact_sha256"
                    ],
                    "functional_requirement_ids": family_spec["functional_requirement_ids"],
                    "functional_requirement_ids_sha256": family_spec[
                        "functional_requirement_ids_sha256"
                    ],
                    "frozen_functional_contracts_path": ("frozen-functional-contracts.jsonl"),
                    "frozen_functional_contracts_sha256": spec[
                        "frozen_functional_contracts_sha256"
                    ],
                    "functional_contract_set_sha256": spec["functional_contract_set_sha256"],
                    "measurement_path": measurement_path.relative_to(root).as_posix(),
                    "measurement_sha256": _sha256_file(measurement_path),
                    "fixture_policy_sha256": fixture_policy_sha256,
                }
            )
    evidence_content = {
        "schema_version": "1.0",
        "role": "judge_tune_overlay_transitive_evidence",
        "source_root_manifest_sha256": spec["source_live_root_manifest_sha256"],
        "frozen_functional_contracts_path": "frozen-functional-contracts.jsonl",
        "frozen_functional_contracts_sha256": spec["frozen_functional_contracts_sha256"],
        "functional_contract_set_sha256": spec["functional_contract_set_sha256"],
        "units": sorted(units, key=lambda row: row["assignment_id"]),
    }
    evidence = {
        "overlay_evidence_id": "overlay_evidence_" + canonical_sha256(evidence_content),
        **evidence_content,
    }
    evidence_path = root / "overlay-evidence-manifest.json"
    _write_json(evidence_path, evidence)
    evidence_sha256 = _sha256_file(evidence_path)
    rows = []
    for core in row_cores:
        content = {**core, "overlay_evidence_manifest_sha256": evidence_sha256}
        rows.append(
            {
                "case_id": "judge_tune_case_" + canonical_sha256(content),
                **content,
            }
        )
    _write_jsonl(root / "judge-tune-cases.jsonl", rows)
    frozen_cases = []
    for family_spec in spec["families"]:
        family_rows = sorted(
            (row for row in rows if row["family"] == family_spec["family"]),
            key=lambda row: row["arm_role"],
        )
        frozen_cases.append(
            {
                "task_id": family_spec["task_id"],
                "family": family_spec["family"],
                "adapter_id": family_rows[0]["adapter_id"],
                "functional_contract": {
                    "contract_id": family_spec["functional_contract_id"],
                    "source_artifact_path": family_spec["functional_contract_source_path"],
                    "source_artifact_sha256": family_spec[
                        "functional_contract_source_artifact_sha256"
                    ],
                    "requirement_ids": family_spec["functional_requirement_ids"],
                    "requirement_ids_sha256": family_spec["functional_requirement_ids_sha256"],
                },
                "arms": [
                    {
                        "assignment_id": row["assignment_id"],
                        "arm_role": row["arm_role"],
                        "assignment_path": f"source-units/{row['assignment_id']}/assignment.jsonl",
                        "assignment_sha256": canonical_sha256(
                            {"assignment_id": row["assignment_id"]}
                        ),
                        "generated_code_path": row["source_artifact_path"],
                        "generated_code_artifact_sha256": row["source_artifact_sha256"],
                        "code_sha256": row["code_sha256"],
                        "functional_contract_path": (
                            f"units/{row['assignment_id']}/functional-contract.jsonl"
                        ),
                        "functional_contract_sha256": family_spec[
                            "functional_contract_source_artifact_sha256"
                        ],
                        "contract_id": family_spec["functional_contract_id"],
                        "unit_manifest_path": (
                            f"source-units/{row['assignment_id']}/artifact-manifest.json"
                        ),
                        "unit_manifest_sha256": canonical_sha256(
                            {"unit_assignment_id": row["assignment_id"]}
                        ),
                    }
                    for row in family_rows
                ],
            }
        )
    contract_summaries = [
        {
            "task_id": family_spec["task_id"],
            "contract_id": family_spec["functional_contract_id"],
            "source_artifact_path": family_spec["functional_contract_source_path"],
            "source_artifact_sha256": family_spec["functional_contract_source_artifact_sha256"],
            "requirement_ids": family_spec["functional_requirement_ids"],
        }
        for family_spec in sorted(spec["families"], key=lambda item: item["task_id"])
    ]
    frozen_plan_content = {
        "schema_version": "1.0",
        "record_type": "executable_functional_sensitivity_preflight",
        "status": "EXECUTABLE_FUNCTIONAL_SENSITIVITY_PREFLIGHT_COMPLETE",
        "execute_requested": True,
        "execution_performed": False,
        "scientific_claim_allowed": False,
        "official_artifact_replacement_allowed": False,
        "source_live_root": "/frozen/live-root",
        "source_root_manifest_sha256": spec["source_live_root_manifest_sha256"],
        "source_root_closure_sha256": source_binding["source_root_closure_sha256"],
        "source_root_provenance_path": "root-provenance.json",
        "source_root_provenance_sha256": spec["source_live_root_provenance_sha256"],
        "source_listed_paths_sha256": source_binding["listed_paths_sha256"],
        "frozen_spec_path": "/frozen/executable-source-spec.json",
        "frozen_spec_sha256": spec["executable_source_spec_sha256"],
        "frozen_spec_id": spec["executable_source_spec_id"],
        "output_dir": "/frozen/calibration-overlay",
        "executor_coordinates": {
            "bwrap_path": executor_policy["sandbox_backend_path"],
            "python_runtime_root": executor_policy["python_runtime_root"],
            "python_relative_executable": "bin/python3.12",
        },
        "zero_execution_counts": {
            "subprocess_calls": 0,
            "generated_code_executions": 0,
            "provider_calls": 0,
            "functional_judge_calls": 0,
            "security_oracle_calls": 0,
        },
        "counts": {"tasks": 4, "assignments": 8},
        "functional_contract_set_sha256": spec["functional_contract_set_sha256"],
        "functional_contracts": contract_summaries,
        "cases": frozen_cases,
    }
    frozen_plan = {
        "preflight_id": "executable_sensitivity_preflight_" + canonical_sha256(frozen_plan_content),
        **frozen_plan_content,
    }
    _write_json(root / "frozen-input-plan.json", frozen_plan)
    frozen_input_plan_sha256 = canonical_sha256(frozen_plan)
    _write_json(
        root / "protocol.json",
        {
            "schema_version": "1.0",
            "functional_variable": "Y_F^E",
            "measurement_method": "deterministic_local_executable_fixture_v1",
            "execution_performed": True,
            "official_artifact_replacement_allowed": False,
            "scientific_claim_allowed": False,
            "controlled_adapter_ids": controlled_adapter_ids,
            "executor_policy": executor_policy,
            "executor_policy_sha256": executor_policy_sha256,
            "sandbox_limitations": [],
            "frozen_input_plan_sha256": frozen_input_plan_sha256,
            "frozen_functional_contracts_path": "frozen-functional-contracts.jsonl",
            "frozen_functional_contracts_sha256": spec["frozen_functional_contracts_sha256"],
            "functional_contract_set_sha256": spec["functional_contract_set_sha256"],
            "command_argv": ["synthetic-isolated-sidecar"],
        },
    )
    paired_results = []
    for family_spec in spec["families"]:
        family_rows = [row for row in rows if row["family"] == family_spec["family"]]
        target = next(row for row in family_rows if row["arm_role"] == "target_patch")
        noop = next(row for row in family_rows if row["arm_role"] == "noop_rewrite")
        paired_results.append(
            {
                "task_id": family_spec["task_id"],
                "family": family_spec["family"],
                "adapter_id": target["adapter_id"],
                "target_y_f_e": target["y_f_e"],
                "noop_y_f_e": noop["y_f_e"],
                "paired_target_minus_noop": target["y_f_e"] - noop["y_f_e"],
            }
        )
    report_content = {
        "schema_version": "1.0",
        "status": "EXECUTABLE_FUNCTIONAL_SENSITIVITY_COMPLETE",
        "role": "post_hoc_development_sensitivity_only",
        "scientific_claim_allowed": False,
        "official_artifact_replacement_allowed": False,
        "functional_variable": "Y_F^E",
        "measurement_method": "deterministic_local_executable_fixture_v1",
        "execution_performed": True,
        "source_binding_id": source_binding["source_binding_id"],
        "source_root_manifest_sha256": spec["source_live_root_manifest_sha256"],
        "executor_policy_sha256": executor_policy_sha256,
        "frozen_input_plan_sha256": frozen_input_plan_sha256,
        "frozen_functional_contracts_path": "frozen-functional-contracts.jsonl",
        "frozen_functional_contracts_sha256": spec["frozen_functional_contracts_sha256"],
        "functional_contract_set_sha256": spec["functional_contract_set_sha256"],
        "sandbox_limitations": [],
        "overlay_evidence_manifest_sha256": evidence_sha256,
        "judge_tune_cases_sha256": _sha256_file(root / "judge-tune-cases.jsonl"),
        "counts": {
            "tasks": 4,
            "assignments": 8,
            "target_assignments": 4,
            "noop_assignments": 4,
            "y_f_e_pass": sum(row["y_f_e"] for row in rows),
            "y_f_e_fail": sum(1 - row["y_f_e"] for row in rows),
            "judge_tune_cases": 8,
            "functional_contracts": 4,
            "provider_calls": 0,
            "security_oracle_calls": 0,
        },
        "paired_results": paired_results,
    }
    _write_json(
        root / "report.json",
        {
            "report_id": "executable_sensitivity_report_" + canonical_sha256(report_content),
            **report_content,
        },
    )
    write_closed_manifest_atomic(root, label="synthetic calibration overlay")


def _build_plan(tmp_path: Path, monkeypatch) -> tuple[Path, object, Path]:
    planner = _load_script("plan_functional_judge_calibration")
    canary = _load_script("validate_bailian_functional_judge")
    spec = json.loads((CALIBRATION_DATA / "calibration-spec.json").read_text(encoding="utf-8"))
    delivery = {
        "status": "PROTOCOL_V2_FULL_LIVE_AND_ANALYSIS_DELIVERED",
        "live": {
            "status": "GATE_C_LIVE_COMPLETE",
            "manifest_sha256": spec["source_live_root_manifest_sha256"],
            "root_provenance_sha256": spec["source_live_root_provenance_sha256"],
            "missing_complete_leaf_units": 0,
        },
    }
    delivery_path = tmp_path / "final-delivery.json"
    _write_json(delivery_path, delivery)
    spec["source_final_delivery_sha256"] = _sha256_file(delivery_path)
    spec_path = tmp_path / "spec.json"
    _write_json(spec_path, spec)
    overlay_dir = tmp_path / "overlay"
    _build_overlay(overlay_dir, spec)
    plan_dir = tmp_path / "plan"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(Path(planner.__file__).resolve()),
            "--spec",
            str(spec_path),
            "--source-final-delivery",
            str(delivery_path),
            "--tune-overlay-dir",
            str(overlay_dir),
            "--validation-cases",
            str(CALIBRATION_DATA / "validation-cases.jsonl"),
            "--output-dir",
            str(plan_dir),
        ],
    )
    assert planner.main() == 0
    return plan_dir, canary, spec_path


def _response(request: dict[str, object], status: str, protocol: str) -> bytes:
    nonblank_line = next(
        row["line_number"] for row in request["program_lines"] if row["text"].strip()
    )
    if protocol == "v1":
        requirements = [
            {
                "requirement_id": row["requirement_id"],
                "verdict": "met" if status == "pass" else "not_met",
                "code_evidence_lines": [nonblank_line],
                "counterexample": (None if status == "pass" else "The frozen behavior is absent."),
            }
            for row in request["requirements"]
        ]
        payload = {
            "status": status,
            "requirements": requirements,
            "rationale": "Frozen calibration response.",
        }
    else:
        requirements = [
            {
                "requirement_id": row["requirement_id"],
                "verdict": "met" if status == "pass" else "not_met",
                "code_evidence_lines": [nonblank_line] if status == "pass" else [],
                "behavior_trace": (
                    "The program follows the frozen behavior." if status == "pass" else None
                ),
                "counterexample": (
                    None
                    if status == "pass"
                    else {
                        "contract_satisfying_scenario": ("The frozen fixture invokes the task."),
                        "expected_behavior": "The required behavior is produced.",
                        "actual_behavior": "The required behavior is absent.",
                    }
                ),
                "unknown_reason": None,
            }
            for row in request["requirements"]
        ]
        payload = {
            "measurement_method": "blind_static_llm_v2",
            "execution_performed": False,
            "status": status,
            "requirements": requirements,
            "rationale": "Frozen calibration response.",
        }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _run_candidate(
    canary,
    monkeypatch,
    plan_dir: Path,
    root: Path,
    config_name: str,
) -> list[Path]:
    protocol = "v1" if config_name.endswith("v1.json") else "v2"
    expected_by_code = {
        "\n".join(row["code_text"].splitlines()): row["expected_status"]
        for row in (
            json.loads(line)
            for line in (plan_dir / "cases.jsonl").read_text(encoding="utf-8").splitlines()
        )
    }

    class Delegate:
        def complete(self, request_bytes: bytes, _policy: object) -> bytes:
            request = json.loads(request_bytes)
            code = "\n".join(row["text"] for row in request["program_lines"])
            return _response(request, expected_by_code[code], protocol)

    monkeypatch.setenv("ALI_BAILIAN_API_KEY", "offline-calibration-key")
    monkeypatch.setattr(
        canary,
        "OpenAICompatibleStructuredTransport",
        lambda **_kwargs: Delegate(),
    )
    results: list[Path] = []
    for slice_name, cases_name in (
        ("pilot", "pilot-cases.jsonl"),
        ("remaining", "remaining-cases.jsonl"),
    ):
        output_dir = root / slice_name
        monkeypatch.setattr(
            sys,
            "argv",
            [
                str(Path(canary.__file__).resolve()),
                "--output-dir",
                str(output_dir),
                "--cases-path",
                str(plan_dir / cases_name),
                "--contracts-path",
                str(plan_dir / "contracts.jsonl"),
                "--evaluator-config",
                str(CALIBRATION_DATA / config_name),
            ],
        )
        assert canary.main() == 0
        results.append(output_dir)
    return results


def test_validation_fixtures_are_16_ast_valid_balanced_cases() -> None:
    rows = [
        json.loads(line)
        for line in (CALIBRATION_DATA / "validation-cases.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert len(rows) == 16
    counts: dict[str, dict[str, int]] = {}
    for row in rows:
        compile(row["code_text"], row["case_id"], "exec")
        family = counts.setdefault(row["family"], {"pass": 0, "fail": 0})
        family[row["expected_status"]] += 1
    assert len(counts) == 4
    assert all(value == {"pass": 2, "fail": 2} for value in counts.values())


@pytest.mark.parametrize(
    ("controlled_adapter_ids", "supported_adapter_ids"),
    (
        (sorted(REAL_EXECUTOR_ADAPTER_ORDER), REAL_EXECUTOR_ADAPTER_ORDER),
        (
            [
                REAL_EXECUTOR_ADAPTER_ORDER[2],
                REAL_EXECUTOR_ADAPTER_ORDER[0],
                REAL_EXECUTOR_ADAPTER_ORDER[3],
                REAL_EXECUTOR_ADAPTER_ORDER[1],
            ],
            list(reversed(REAL_EXECUTOR_ADAPTER_ORDER)),
        ),
    ),
)
def test_planner_accepts_exact_unique_adapter_sets_in_any_order(
    tmp_path: Path,
    controlled_adapter_ids: list[object],
    supported_adapter_ids: list[object],
) -> None:
    planner = _load_script("plan_functional_judge_calibration")
    spec_path = CALIBRATION_DATA / "calibration-spec.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    _spec, family_specs = planner._load_spec(spec_path)
    overlay = tmp_path / "adapter-order-overlay"
    _build_overlay(
        overlay,
        spec,
        controlled_adapter_ids=controlled_adapter_ids,
        supported_adapter_ids=supported_adapter_ids,
    )

    rows, _manifest, _evidence, _contracts = planner._load_tune_rows(overlay, spec, family_specs)

    assert len(rows) == 8


@pytest.mark.parametrize("field", ("controlled_adapter_ids", "supported_adapter_ids"))
@pytest.mark.parametrize(
    "invalid_adapter_ids",
    (
        REAL_EXECUTOR_ADAPTER_ORDER[:-1] + [REAL_EXECUTOR_ADAPTER_ORDER[0]],
        REAL_EXECUTOR_ADAPTER_ORDER[:-1],
        REAL_EXECUTOR_ADAPTER_ORDER + ["unexpected_adapter_v1"],
        REAL_EXECUTOR_ADAPTER_ORDER[:-1] + [7],
    ),
    ids=("duplicate", "missing", "extra", "non-string"),
)
def test_planner_rejects_non_exact_or_non_unique_adapter_sets(
    tmp_path: Path,
    field: str,
    invalid_adapter_ids: list[object],
) -> None:
    planner = _load_script("plan_functional_judge_calibration")
    spec_path = CALIBRATION_DATA / "calibration-spec.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    _spec, family_specs = planner._load_spec(spec_path)
    overlay = tmp_path / "o"
    overrides = {field: invalid_adapter_ids}
    _build_overlay(overlay, spec, **overrides)

    with pytest.raises(ValueError, match="isolated executor protocol"):
        planner._load_tune_rows(overlay, spec, family_specs)


def test_planner_rejects_reclosed_measurement_semantic_binding_attack(tmp_path: Path) -> None:
    planner = _load_script("plan_functional_judge_calibration")
    spec = json.loads((CALIBRATION_DATA / "calibration-spec.json").read_text(encoding="utf-8"))
    _spec, family_specs = planner._load_spec(CALIBRATION_DATA / "calibration-spec.json")
    overlay = tmp_path / "attacked-overlay"
    _build_overlay(
        overlay,
        spec,
        measurement_binding_attack=True,
    )

    with pytest.raises(ValueError, match="measurement binding"):
        planner._load_tune_rows(
            overlay,
            spec,
            family_specs,
        )


def test_planner_rejects_reclosed_raw_fixture_evidence_attack(tmp_path: Path) -> None:
    planner = _load_script("plan_functional_judge_calibration")
    spec = json.loads((CALIBRATION_DATA / "calibration-spec.json").read_text(encoding="utf-8"))
    _spec, family_specs = planner._load_spec(CALIBRATION_DATA / "calibration-spec.json")
    overlay = tmp_path / "raw-evidence-attacked-overlay"
    _build_overlay(
        overlay,
        spec,
        raw_evidence_attack=True,
    )

    with pytest.raises(ValueError, match="raw evidence binding"):
        planner._load_tune_rows(
            overlay,
            spec,
            family_specs,
        )


def test_planner_rejects_reclosed_legacy_weak_executor_overlay(tmp_path: Path) -> None:
    planner = _load_script("plan_functional_judge_calibration")
    spec_path = CALIBRATION_DATA / "calibration-spec.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    _spec, family_specs = planner._load_spec(spec_path)
    overlay = tmp_path / "weak-executor-overlay"
    _build_overlay(
        overlay,
        spec,
        weak_executor_attack=True,
    )

    with pytest.raises(ValueError, match="isolated executor protocol"):
        planner._load_tune_rows(
            overlay,
            spec,
            family_specs,
        )


def test_planner_rejects_reclosed_same_task_forged_contracts(tmp_path: Path) -> None:
    planner = _load_script("plan_functional_judge_calibration")
    spec_path = CALIBRATION_DATA / "calibration-spec.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    _spec, family_specs = planner._load_spec(spec_path)
    overlay = tmp_path / "forged-contract-overlay"
    _build_overlay(overlay, spec)
    (overlay / "artifact-manifest.json").unlink()
    contracts_path = overlay / "frozen-functional-contracts.jsonl"
    contracts = [
        json.loads(line) for line in contracts_path.read_text(encoding="utf-8").splitlines()
    ]
    attacked = contracts[0]
    attacked["requirements"][0]["criterion"] = (
        "A forged criterion with the same frozen task coordinate."
    )
    content = {
        key: value
        for key, value in attacked.items()
        if key not in {"contract_id", "schema_version"}
    }
    contracts[0] = TaskFunctionalContractRecord.from_content(**content).model_dump(mode="json")
    _write_jsonl(contracts_path, contracts)
    write_closed_manifest_atomic(overlay, label="reclosed forged contract overlay")

    with pytest.raises(ValueError, match="contract artifact digest"):
        planner._load_tune_rows(overlay, spec, family_specs)


def test_analyzer_rejects_reclosed_plan_gold_rewrite(monkeypatch, tmp_path: Path) -> None:
    plan_dir, _canary, calibration_spec_path = _build_plan(tmp_path, monkeypatch)
    analyzer = _load_script("analyze_functional_judge_calibration")
    expected_plan = json.loads((plan_dir / "plan.json").read_text(encoding="utf-8"))
    expected_manifest_sha256 = _sha256_file(plan_dir / "artifact-manifest.json")
    attacked = tmp_path / "reclosed-plan-gold-rewrite"
    shutil.copytree(plan_dir, attacked)
    (attacked / "artifact-manifest.json").unlink()
    cases = [
        json.loads(line)
        for line in (attacked / "cases.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    metadata = [
        json.loads(line)
        for line in (attacked / "calibration-case-metadata.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    validation_case = next(row for row in metadata if row["split"] == "validation")
    new_status = "pass" if validation_case["expected_status"] == "fail" else "fail"
    validation_case["expected_status"] = new_status
    next(row for row in cases if row["case_id"] == validation_case["case_id"])[
        "expected_status"
    ] = new_status
    remaining = [
        json.loads(line)
        for line in (attacked / "remaining-cases.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    next(row for row in remaining if row["case_id"] == validation_case["case_id"])[
        "expected_status"
    ] = new_status
    _write_jsonl(attacked / "cases.jsonl", cases)
    _write_jsonl(attacked / "remaining-cases.jsonl", remaining)
    _write_jsonl(attacked / "calibration-case-metadata.jsonl", metadata)
    attacked_plan = json.loads((attacked / "plan.json").read_text(encoding="utf-8"))
    attacked_plan["provider_cases_sha256"] = canonical_sha256(cases)
    attacked_plan["case_metadata_sha256"] = canonical_sha256(metadata)
    attacked_core = {key: value for key, value in attacked_plan.items() if key != "plan_id"}
    attacked_plan["plan_id"] = "functional_judge_calibration_plan_" + canonical_sha256(
        attacked_core
    )
    _write_json(attacked / "plan.json", attacked_plan)
    write_closed_manifest_atomic(attacked, label="reclosed attacked calibration plan")

    with pytest.raises(ValueError, match="plan authority"):
        analyzer._load_plan(
            attacked,
            calibration_spec_path=calibration_spec_path,
            expected_plan_id=expected_plan["plan_id"],
            expected_root_manifest_sha256=expected_manifest_sha256,
        )


def test_analyzer_closes_artifacts_excludes_baseline_and_rejects_trace_attack(
    monkeypatch, tmp_path: Path
) -> None:
    plan_dir, canary, calibration_spec_path = _build_plan(tmp_path, monkeypatch)
    analyzer = _load_script("analyze_functional_judge_calibration")
    baseline_runs = _run_candidate(
        canary,
        monkeypatch,
        plan_dir,
        tmp_path / "baseline",
        "evaluator-qwen35flash-v1.json",
    )
    new_runs = _run_candidate(
        canary,
        monkeypatch,
        plan_dir,
        tmp_path / "new",
        "evaluator-qwen35flash-v2.json",
    )
    analysis_dir = tmp_path / "analysis"
    plan_record = json.loads((plan_dir / "plan.json").read_text(encoding="utf-8"))
    plan_authority_args = [
        "--calibration-spec",
        str(calibration_spec_path),
        "--expected-plan-id",
        plan_record["plan_id"],
        "--expected-plan-root-manifest-sha256",
        _sha256_file(plan_dir / "artifact-manifest.json"),
    ]
    argv = [
        str(Path(analyzer.__file__).resolve()),
        "--plan-dir",
        str(plan_dir),
        *plan_authority_args,
        *[
            value
            for path in [*baseline_runs, *new_runs]
            for value in ("--candidate-run-dir", str(path))
        ],
        "--output-dir",
        str(analysis_dir),
    ]
    monkeypatch.setattr(sys, "argv", argv)
    assert analyzer.main() == 0
    report = json.loads((analysis_dir / "report.json").read_text(encoding="utf-8"))
    summaries = {row["candidate_role"]: row for row in report["candidate_summaries"]}
    assert report["selected_candidate_id"] == "qwen35flash-prompt-v2"
    assert summaries["baseline"]["eligible_for_selection"] is False
    assert summaries["baseline"]["selection_exclusion_reason"] == "baseline_comparison_only"
    assert summaries["new_candidate"]["eligible_for_selection"] is True
    assert report["new_calls"]["functional_judge_provider_attempts"] == 48
    assert set(summaries["new_candidate"]["tune_by_arm"]) == {
        "noop_rewrite",
        "target_patch",
    }

    bad_pilot = tmp_path / "attacked-new-pilot"
    shutil.copytree(new_runs[0], bad_pilot)
    (bad_pilot / "artifact-manifest.json").unlink()
    trace_path = bad_pilot / "llm_exchange_trace.jsonl"
    traces = [json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines()]
    traces[0]["evaluator_policy_sha256"] = "f" * 64
    _write_jsonl(trace_path, traces)
    write_closed_manifest_atomic(bad_pilot, label="reclosed attacked candidate run")
    failed_dir = tmp_path / "failed-analysis"
    bad_argv = [
        str(Path(analyzer.__file__).resolve()),
        "--plan-dir",
        str(plan_dir),
        *plan_authority_args,
        *[
            value
            for path in [*baseline_runs, bad_pilot, new_runs[1]]
            for value in ("--candidate-run-dir", str(path))
        ],
        "--output-dir",
        str(failed_dir),
    ]
    monkeypatch.setattr(sys, "argv", bad_argv)
    assert analyzer.main() == 1
    failed = json.loads((failed_dir / "report.json").read_text(encoding="utf-8"))
    assert failed["selected_candidate_id"] is None
    failed_new = next(
        row for row in failed["candidate_summaries"] if row["candidate_role"] == "new_candidate"
    )
    assert failed_new["gates"]["provider_attempt_and_artifact_closure"] is False

    bad_pass_pilot = tmp_path / "attacked-pass-new-pilot"
    shutil.copytree(new_runs[0], bad_pass_pilot)
    (bad_pass_pilot / "artifact-manifest.json").unlink()
    passes_path = bad_pass_pilot / "functional_judge_passes.jsonl"
    outcomes_path = bad_pass_pilot / "program_functional_outcomes.jsonl"
    report_path = bad_pass_pilot / "report.json"
    pass_rows = [json.loads(line) for line in passes_path.read_text(encoding="utf-8").splitlines()]
    outcome_rows = [
        json.loads(line) for line in outcomes_path.read_text(encoding="utf-8").splitlines()
    ]
    original = pass_rows[0]
    attacked_requirements = original["requirements"]
    attacked_requirements[0] = {
        **attacked_requirements[0],
        "verdict": "not_met",
        "counterexample": "A self-consistent forged pass contradicts the raw response.",
    }
    forged_pass = FunctionalJudgePassRecord.from_content(
        assignment_id=original["assignment_id"],
        contract_id=original["contract_id"],
        pass_id="A",
        evaluator_policy_sha256=original["evaluator_policy_sha256"],
        request_sha256=original["request_sha256"],
        response_sha256=original["response_sha256"],
        status="fail",
        requirements=attacked_requirements,
        rationale="The forged persisted pass says fail.",
    )
    pass_rows[0] = forged_pass.model_dump(mode="json")
    forged_evidence = canonical_sha256(
        {
            "schema_version": "1.0",
            "pass_ids": [forged_pass.judge_pass_id],
            "decision": "fail",
            "mode": "single_pass",
        }
    )
    forged_outcome = ProgramFunctionalOutcomeRecord.from_content(
        assignment_id=forged_pass.assignment_id,
        contract_id=forged_pass.contract_id,
        evaluator_policy_sha256=forged_pass.evaluator_policy_sha256,
        status="fail",
        evidence_sha256=forged_evidence,
    )
    outcome_index = next(
        index
        for index, row in enumerate(outcome_rows)
        if row["assignment_id"] == forged_pass.assignment_id
    )
    outcome_rows[outcome_index] = forged_outcome.model_dump(mode="json")
    report_payload = json.loads(report_path.read_text(encoding="utf-8"))
    report_result = next(
        row
        for row in report_payload["case_results"]
        if row["assignment_id"] == forged_pass.assignment_id
    )
    report_result["actual_status"] = "fail"
    report_result["pass_statuses"] = ["fail"]
    report_payload["status"] = "FAIL"
    report_payload["artifact_sha256"]["passes"] = canonical_sha256(pass_rows)
    report_payload["artifact_sha256"]["outcomes"] = canonical_sha256(outcome_rows)
    _write_jsonl(passes_path, pass_rows)
    _write_jsonl(outcomes_path, outcome_rows)
    _write_json(report_path, report_payload)
    write_closed_manifest_atomic(bad_pass_pilot, label="reclosed forged pass candidate run")
    forged_dir = tmp_path / "forged-pass-analysis"
    forged_argv = [
        str(Path(analyzer.__file__).resolve()),
        "--plan-dir",
        str(plan_dir),
        *plan_authority_args,
        *[
            value
            for path in [*baseline_runs, bad_pass_pilot, new_runs[1]]
            for value in ("--candidate-run-dir", str(path))
        ],
        "--output-dir",
        str(forged_dir),
    ]
    monkeypatch.setattr(sys, "argv", forged_argv)
    assert analyzer.main() == 1
    forged_cases = [
        json.loads(line)
        for line in (forged_dir / "case-results.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert any(
        "raw_response_pass_rebuild_mismatch" in row["closure_errors"] for row in forged_cases
    )

    early_remaining = tmp_path / "early-new-remaining"
    shutil.copytree(new_runs[1], early_remaining)
    (early_remaining / "artifact-manifest.json").unlink()
    early_report_path = early_remaining / "report.json"
    early_report = json.loads(early_report_path.read_text(encoding="utf-8"))
    early_report["started_at_utc"] = "2000-01-01T00:00:00+00:00"
    early_report["completed_at_utc"] = "2000-01-01T00:01:00+00:00"
    _write_json(early_report_path, early_report)
    write_closed_manifest_atomic(early_remaining, label="reclosed early remaining run")
    phase_argv = [
        str(Path(analyzer.__file__).resolve()),
        "--plan-dir",
        str(plan_dir),
        *plan_authority_args,
        *[
            value
            for path in [*baseline_runs, new_runs[0], early_remaining]
            for value in ("--candidate-run-dir", str(path))
        ],
        "--output-dir",
        str(tmp_path / "phase-attack-analysis"),
    ]
    monkeypatch.setattr(sys, "argv", phase_argv)
    with pytest.raises(SystemExit, match="ValueError"):
        analyzer.main()

    error_status_pilot = tmp_path / "error-status-new-pilot"
    shutil.copytree(new_runs[0], error_status_pilot)
    (error_status_pilot / "artifact-manifest.json").unlink()
    error_report_path = error_status_pilot / "report.json"
    error_report = json.loads(error_report_path.read_text(encoding="utf-8"))
    error_report["status"] = "ERROR"
    _write_json(error_report_path, error_report)
    write_closed_manifest_atomic(
        error_status_pilot,
        label="reclosed nonterminal candidate run",
    )
    error_status_argv = [
        str(Path(analyzer.__file__).resolve()),
        "--plan-dir",
        str(plan_dir),
        *plan_authority_args,
        *[
            value
            for path in [*baseline_runs, error_status_pilot, new_runs[1]]
            for value in ("--candidate-run-dir", str(path))
        ],
        "--output-dir",
        str(tmp_path / "error-status-analysis"),
    ]
    monkeypatch.setattr(sys, "argv", error_status_argv)
    with pytest.raises(SystemExit, match="ValueError"):
        analyzer.main()

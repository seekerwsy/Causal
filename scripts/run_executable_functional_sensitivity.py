"""Preflight and run the four-task executable-functional sensitivity sidecar.

The default mode performs no subprocess, provider, Judge, Oracle, or generated-
code execution.  It verifies the frozen live-root closure, mechanically binds
the eight canonical generated-code records, and prints one canonical JSON plan.
Pass ``--execute`` to print that plan first and then run the Bubblewrap executor.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from secaware.canonical import canonical_sha256
from secaware.exploratory.artifact_integrity import verify_closed_manifest
from secaware.exploratory.executable_functional_sensitivity import (
    ArmArtifactBinding,
    ExecutableSensitivityCase,
    FrozenFunctionalContractBinding,
    GtfFastaAppendCliAdapter,
    IsolatedSubprocessExecutorV1,
    PdfPdftotextBagOfWordsAdapter,
    SlurmSacctSqueueAdapter,
    SQLiteMetadataPragmaAdapter,
    run_executable_functional_sensitivity,
)
from secaware.functional_judge.schema import TaskFunctionalContractRecord
from secaware.pipeline.artifact import sha256_file
from secaware.schema.experiments import AssignmentRecord
from secaware.schema.records import CanonicalGeneratedCodeRecord

_SCHEMA_VERSION = "1.0"
_ASSIGNMENT_ID = re.compile(r"^assignment_[0-9a-f]{64}$")
_TASK_ID = re.compile(r"^secaware_main_task_[0-9a-f]{64}$")
_CONTRACT_ID = re.compile(r"^functional_contract_[0-9a-f]{64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ADAPTERS = {
    adapter.family: adapter
    for adapter in (
        GtfFastaAppendCliAdapter(),
        SQLiteMetadataPragmaAdapter(),
        PdfPdftotextBagOfWordsAdapter(),
        SlurmSacctSqueueAdapter(),
    )
}


@dataclass(frozen=True, slots=True)
class _SourceSnapshot:
    manifest_sha256: str
    closure_sha256: str
    entries: tuple[tuple[str, str], ...]


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _read_json_object(path: Path) -> tuple[dict[str, object], str]:
    raw = path.read_bytes()
    try:
        value: Any = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"JSON object failed validation: {path}") from error
    if type(value) is not dict:
        raise ValueError(f"JSON object failed validation: {path}")
    return value, hashlib.sha256(raw).hexdigest()


def _manifest_entries(manifest: dict[str, object]) -> tuple[tuple[str, str], ...]:
    files = manifest.get("files")
    if type(files) is not list:
        raise ValueError("source manifest entries failed validation")
    result: list[tuple[str, str]] = []
    for item in files:
        if (
            type(item) is not dict
            or set(item) != {"path", "sha256"}
            or type(item.get("path")) is not str
            or type(item.get("sha256")) is not str
            or _SHA256.fullmatch(str(item["sha256"])) is None
        ):
            raise ValueError("source manifest entry failed validation")
        result.append((str(item["path"]), str(item["sha256"])))
    return tuple(sorted(result))


def _source_snapshot(manifest_path: Path) -> _SourceSnapshot:
    verified = verify_closed_manifest(manifest_path, label="executable sensitivity CLI source")
    return _SourceSnapshot(
        manifest_sha256=sha256_file(manifest_path),
        closure_sha256=canonical_sha256(verified),
        entries=_manifest_entries(verified),
    )


def _assert_source_snapshot(manifest_path: Path, expected: _SourceSnapshot) -> None:
    if sha256_file(manifest_path) != expected.manifest_sha256:
        raise ValueError("source manifest changed during executable-sensitivity preflight")
    if _source_snapshot(manifest_path) != expected:
        raise ValueError("source closure changed during executable-sensitivity preflight")


def _spec_cases(spec: dict[str, object]) -> tuple[str, list[dict[str, object]]]:
    source_sha = spec.get("source_live_root_manifest_sha256")
    raw_cases = spec.get("cases")
    spec_id = spec.get("spec_id")
    spec_content = dict(spec)
    spec_content.pop("spec_id", None)
    if (
        set(spec)
        != {
            "schema_version",
            "spec_id",
            "source_live_root_manifest_sha256",
            "source_live_root_provenance_sha256",
            "cases",
        }
        or spec.get("schema_version") != _SCHEMA_VERSION
        or type(spec_id) is not str
        or spec_id != "executable_sensitivity_source_spec_" + canonical_sha256(spec_content)
        or type(source_sha) is not str
        or _SHA256.fullmatch(source_sha) is None
        or type(spec.get("source_live_root_provenance_sha256")) is not str
        or _SHA256.fullmatch(str(spec["source_live_root_provenance_sha256"])) is None
        or type(raw_cases) is not list
        or len(raw_cases) != 4
    ):
        raise ValueError("frozen executable-sensitivity spec failed validation")
    cases: list[dict[str, object]] = []
    seen_tasks: set[str] = set()
    seen_assignments: set[str] = set()
    seen_families: set[str] = set()
    for item in raw_cases:
        if type(item) is not dict or set(item) != {
            "task_id",
            "family",
            "adapter_id",
            "contract",
            "arms",
        }:
            raise ValueError("frozen executable-sensitivity family failed validation")
        family = item.get("family")
        task_id = item.get("task_id")
        adapter_id = item.get("adapter_id")
        contract = item.get("contract")
        arms = item.get("arms")
        if (
            type(family) is not str
            or family not in _ADAPTERS
            or family in seen_families
            or adapter_id != _ADAPTERS[family].adapter_id
            or type(task_id) is not str
            or _TASK_ID.fullmatch(task_id) is None
            or task_id in seen_tasks
            or type(contract) is not dict
            or set(contract) != {"contract_id", "artifact_sha256", "requirements"}
            or type(contract.get("contract_id")) is not str
            or _CONTRACT_ID.fullmatch(str(contract["contract_id"])) is None
            or type(contract.get("artifact_sha256")) is not str
            or _SHA256.fullmatch(str(contract["artifact_sha256"])) is None
            or type(contract.get("requirements")) is not list
            or not contract["requirements"]
            or type(arms) is not list
            or len(arms) != 2
        ):
            raise ValueError("frozen executable-sensitivity family failed validation")
        for requirement in contract["requirements"]:
            if (
                type(requirement) is not dict
                or set(requirement) != {"requirement_id", "kind", "criterion"}
                or any(
                    type(requirement.get(key)) is not str
                    or not str(requirement[key])
                    or str(requirement[key]) != str(requirement[key]).strip()
                    for key in ("requirement_id", "kind", "criterion")
                )
            ):
                raise ValueError("frozen executable-sensitivity requirement failed validation")
        requirement_ids = tuple(
            str(requirement["requirement_id"]) for requirement in contract["requirements"]
        )
        if requirement_ids != tuple(
            rule.requirement_id for rule in _ADAPTERS[family].requirement_rules
        ):
            raise ValueError("frozen executable-sensitivity requirement coverage failed validation")
        assignment_ids: list[str] = []
        roles: set[str] = set()
        for arm in arms:
            if (
                type(arm) is not dict
                or set(arm)
                != {
                    "assignment_id",
                    "arm_role",
                    "unit_manifest_sha256",
                    "assignment_artifact_sha256",
                    "generated_code_artifact_sha256",
                    "code_sha256",
                }
                or type(arm.get("assignment_id")) is not str
                or _ASSIGNMENT_ID.fullmatch(str(arm["assignment_id"])) is None
                or arm.get("arm_role") not in {"target_patch", "noop_rewrite"}
                or any(
                    type(arm.get(key)) is not str or _SHA256.fullmatch(str(arm[key])) is None
                    for key in (
                        "unit_manifest_sha256",
                        "assignment_artifact_sha256",
                        "generated_code_artifact_sha256",
                        "code_sha256",
                    )
                )
            ):
                raise ValueError("frozen executable-sensitivity arm failed validation")
            assignment_ids.append(str(arm["assignment_id"]))
            roles.add(str(arm["arm_role"]))
        if (
            len(set(assignment_ids)) != 2
            or roles != {"target_patch", "noop_rewrite"}
            or any(value in seen_assignments for value in assignment_ids)
        ):
            raise ValueError("frozen executable-sensitivity arm coverage failed validation")
        seen_families.add(family)
        seen_tasks.add(task_id)
        seen_assignments.update(assignment_ids)
        cases.append(item)
    if seen_families != set(_ADAPTERS) or len(seen_assignments) != 8:
        raise ValueError("frozen executable-sensitivity coverage failed validation")
    return source_sha, sorted(cases, key=lambda item: str(item["task_id"]))


def _one_model(path: Path, digest: str, model: type[Any]) -> Any:
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError(f"source record digest failed validation: {path}")
    try:
        decoded = raw.decode("utf-8")
    except UnicodeError as error:
        raise ValueError(f"source record failed UTF-8 validation: {path}") from error
    lines = decoded.splitlines()
    if len(lines) != 1 or not lines[0]:
        raise ValueError(f"source record count failed validation: {path}")
    return model.model_validate_json(lines[0])


def build_preflight(
    *,
    source_live_root: Path,
    frozen_spec_path: Path,
    bwrap_path: Path,
    python_runtime_root: Path,
    python_relative_executable: str,
    output_dir: Path,
    execute_requested: bool,
) -> tuple[dict[str, object], tuple[ExecutableSensitivityCase, ...]]:
    source_live_root = source_live_root.resolve(strict=True)
    frozen_spec_path = frozen_spec_path.resolve(strict=True)
    bwrap_path = bwrap_path.resolve(strict=True)
    python_runtime_root = python_runtime_root.resolve(strict=True)
    output_dir = output_dir.resolve()
    if (
        not source_live_root.is_dir()
        or not python_runtime_root.is_dir()
        or not bwrap_path.is_file()
    ):
        raise ValueError("preflight path type failed validation")
    if output_dir.exists():
        raise FileExistsError(output_dir)
    relative_python = Path(python_relative_executable)
    if (
        not python_relative_executable
        or relative_python.is_absolute()
        or relative_python.as_posix() != python_relative_executable
        or any(part in {"", ".", ".."} for part in relative_python.parts)
        or not (python_runtime_root / relative_python).resolve(strict=True).is_file()
    ):
        raise ValueError("preflight Python runtime executable failed validation")
    source_manifest_path = source_live_root / "artifact-manifest.json"
    snapshot = _source_snapshot(source_manifest_path)
    spec, spec_sha256 = _read_json_object(frozen_spec_path)
    expected_source_sha, spec_cases = _spec_cases(spec)
    if snapshot.manifest_sha256 != expected_source_sha:
        raise ValueError("frozen spec source manifest binding failed validation")
    root_entries = dict(snapshot.entries)
    source_provenance_sha256 = str(spec["source_live_root_provenance_sha256"])
    if root_entries.get("root-provenance.json") != source_provenance_sha256:
        raise ValueError("frozen spec source provenance binding failed validation")
    cases: list[ExecutableSensitivityCase] = []
    discovered_cases: list[dict[str, object]] = []
    for case_spec in spec_cases:
        task_id = str(case_spec["task_id"])
        family = str(case_spec["family"])
        adapter = _ADAPTERS[family]
        arms: list[ArmArtifactBinding] = []
        discovered_arms: list[dict[str, object]] = []
        contract_spec = case_spec["contract"]
        if type(contract_spec) is not dict:  # pragma: no cover - narrowed by _spec_cases
            raise ValueError("frozen contract failed validation")
        arm_specs = case_spec["arms"]
        if type(arm_specs) is not list:  # pragma: no cover - narrowed by _spec_cases
            raise ValueError("frozen arms failed validation")
        for arm_spec in arm_specs:
            if type(arm_spec) is not dict:  # pragma: no cover - narrowed by _spec_cases
                raise ValueError("frozen arm failed validation")
            assignment_id = str(arm_spec["assignment_id"])
            prefix = f"units/{assignment_id}"
            paths = {
                "unit_manifest": f"{prefix}/artifact-manifest.json",
                "assignment": f"{prefix}/assignment.jsonl",
                "generated_code": f"{prefix}/generated-code.jsonl",
                "contract": f"{prefix}/functional-contract.jsonl",
            }
            if any(path not in root_entries for path in paths.values()):
                raise ValueError("source unit is not fully bound by the root manifest")
            expected_digests = {
                "unit_manifest": str(arm_spec["unit_manifest_sha256"]),
                "assignment": str(arm_spec["assignment_artifact_sha256"]),
                "generated_code": str(arm_spec["generated_code_artifact_sha256"]),
                "contract": str(contract_spec["artifact_sha256"]),
            }
            if any(
                root_entries[paths[name]] != digest for name, digest in expected_digests.items()
            ):
                raise ValueError("source unit differs from the tracked frozen spec")
            unit_manifest_path = source_live_root / paths["unit_manifest"]
            if sha256_file(unit_manifest_path) != expected_digests["unit_manifest"]:
                raise ValueError("source unit manifest digest failed validation")
            unit_manifest = verify_closed_manifest(
                unit_manifest_path,
                label=f"executable sensitivity source unit {assignment_id}",
            )
            unit_entries = dict(_manifest_entries(unit_manifest))
            for name in ("assignment", "generated_code", "contract"):
                unit_relative = Path(paths[name]).name
                if unit_entries.get(unit_relative) != expected_digests[name]:
                    raise ValueError("source unit/root manifest binding failed validation")
            assignment = _one_model(
                source_live_root / paths["assignment"],
                expected_digests["assignment"],
                AssignmentRecord,
            )
            code = _one_model(
                source_live_root / paths["generated_code"],
                expected_digests["generated_code"],
                CanonicalGeneratedCodeRecord,
            )
            contract = _one_model(
                source_live_root / paths["contract"],
                expected_digests["contract"],
                TaskFunctionalContractRecord,
            )
            role = assignment.arm_role.value
            code_role = code.arm_role.value if code.arm_role is not None else None
            observed_requirements = [
                {
                    "requirement_id": item.requirement_id,
                    "kind": item.kind,
                    "criterion": item.criterion,
                }
                for item in contract.requirements
            ]
            if (
                assignment.assignment_id != assignment_id
                or assignment.experimental_unit.task_id != task_id
                or role not in {"target_patch", "noop_rewrite"}
                or role != arm_spec["arm_role"]
                or code.condition != "confirm_arm"
                or code.assignment_id != assignment_id
                or code_role != role
                or type(code.code_sha256) is not str
                or code.code_sha256 != arm_spec["code_sha256"]
                or contract.task_id != task_id
                or contract.contract_id != contract_spec["contract_id"]
                or observed_requirements != contract_spec["requirements"]
            ):
                raise ValueError("source assignment/code coordinate binding failed validation")
            binding = ArmArtifactBinding(
                assignment_id=assignment_id,
                task_id=task_id,
                arm_role=role,
                artifact_relative_path=paths["generated_code"],
                artifact_sha256=expected_digests["generated_code"],
                code_sha256=code.code_sha256,
                artifact_format="canonical_generated_code_jsonl_v1",
            )
            arms.append(binding)
            discovered_arms.append(
                {
                    "assignment_id": assignment_id,
                    "arm_role": role,
                    "assignment_path": paths["assignment"],
                    "assignment_sha256": expected_digests["assignment"],
                    "generated_code_path": paths["generated_code"],
                    "generated_code_artifact_sha256": expected_digests["generated_code"],
                    "code_sha256": code.code_sha256,
                    "functional_contract_path": paths["contract"],
                    "functional_contract_sha256": expected_digests["contract"],
                    "contract_id": contract.contract_id,
                    "unit_manifest_path": paths["unit_manifest"],
                    "unit_manifest_sha256": expected_digests["unit_manifest"],
                }
            )
            _assert_source_snapshot(source_manifest_path, snapshot)
        if {arm.arm_role for arm in arms} != {"target_patch", "noop_rewrite"}:
            raise ValueError("source task does not contain the exact paired arm protocol")
        ordered_arms = tuple(sorted(arms, key=lambda arm: arm.arm_role))
        target_arm_spec = next(item for item in arm_specs if item["arm_role"] == "target_patch")
        contract_source_path = f"units/{target_arm_spec['assignment_id']}/functional-contract.jsonl"
        requirement_ids = tuple(
            str(item["requirement_id"]) for item in contract_spec["requirements"]
        )
        contract_binding = FrozenFunctionalContractBinding(
            task_id=task_id,
            contract_id=str(contract_spec["contract_id"]),
            artifact_relative_path=contract_source_path,
            artifact_sha256=str(contract_spec["artifact_sha256"]),
            requirement_ids=requirement_ids,
        )
        cases.append(
            ExecutableSensitivityCase(
                task_id=task_id,
                family=family,
                adapter=adapter,
                arms=(ordered_arms[0], ordered_arms[1]),
                functional_contract=contract_binding,
            )
        )
        discovered_cases.append(
            {
                "task_id": task_id,
                "family": family,
                "adapter_id": adapter.adapter_id,
                "functional_contract": {
                    "contract_id": contract_binding.contract_id,
                    "source_artifact_path": contract_binding.artifact_relative_path,
                    "source_artifact_sha256": contract_binding.artifact_sha256,
                    "requirement_ids": list(contract_binding.requirement_ids),
                    "requirement_ids_sha256": canonical_sha256(
                        list(contract_binding.requirement_ids)
                    ),
                },
                "arms": sorted(discovered_arms, key=lambda item: str(item["arm_role"])),
            }
        )
    _assert_source_snapshot(source_manifest_path, snapshot)
    contract_summaries = [
        {
            "task_id": item["task_id"],
            "contract_id": item["functional_contract"]["contract_id"],
            "source_artifact_path": item["functional_contract"]["source_artifact_path"],
            "source_artifact_sha256": item["functional_contract"]["source_artifact_sha256"],
            "requirement_ids": item["functional_contract"]["requirement_ids"],
        }
        for item in sorted(discovered_cases, key=lambda value: str(value["task_id"]))
    ]
    plan_content = {
        "schema_version": _SCHEMA_VERSION,
        "record_type": "executable_functional_sensitivity_preflight",
        "status": "EXECUTABLE_FUNCTIONAL_SENSITIVITY_PREFLIGHT_COMPLETE",
        "execute_requested": execute_requested,
        "execution_performed": False,
        "scientific_claim_allowed": False,
        "official_artifact_replacement_allowed": False,
        "source_live_root": str(source_live_root),
        "source_root_manifest_sha256": snapshot.manifest_sha256,
        "source_root_closure_sha256": snapshot.closure_sha256,
        "source_root_provenance_path": "root-provenance.json",
        "source_root_provenance_sha256": source_provenance_sha256,
        "source_listed_paths_sha256": canonical_sha256(
            [path for path, _digest in snapshot.entries]
        ),
        "frozen_spec_path": str(frozen_spec_path),
        "frozen_spec_sha256": spec_sha256,
        "frozen_spec_id": spec.get("spec_id"),
        "output_dir": str(output_dir),
        "executor_coordinates": {
            "bwrap_path": str(bwrap_path),
            "python_runtime_root": str(python_runtime_root),
            "python_relative_executable": python_relative_executable,
        },
        "zero_execution_counts": {
            "subprocess_calls": 0,
            "generated_code_executions": 0,
            "provider_calls": 0,
            "functional_judge_calls": 0,
            "security_oracle_calls": 0,
        },
        "counts": {"tasks": len(cases), "assignments": sum(len(case.arms) for case in cases)},
        "functional_contract_set_sha256": canonical_sha256(contract_summaries),
        "functional_contracts": contract_summaries,
        "cases": discovered_cases,
    }
    return (
        {
            "preflight_id": "executable_sensitivity_preflight_" + canonical_sha256(plan_content),
            **plan_content,
        },
        tuple(cases),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Preflight or run the frozen four-task executable-functional sensitivity."
    )
    parser.add_argument("--source-live-root", type=Path, required=True)
    parser.add_argument("--frozen-spec", type=Path, required=True)
    parser.add_argument("--bwrap", type=Path, required=True)
    parser.add_argument("--python-runtime", type=Path, required=True)
    parser.add_argument("--python-relative-executable", default="bin/python3.12")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    plan, cases = build_preflight(
        source_live_root=arguments.source_live_root,
        frozen_spec_path=arguments.frozen_spec,
        bwrap_path=arguments.bwrap,
        python_runtime_root=arguments.python_runtime,
        python_relative_executable=arguments.python_relative_executable,
        output_dir=arguments.output_dir,
        execute_requested=arguments.execute,
    )
    print(_canonical(plan), flush=True)
    if not arguments.execute:
        return 0
    executor = IsolatedSubprocessExecutorV1(
        bwrap_executable=arguments.bwrap,
        python_runtime_root=arguments.python_runtime,
        python_relative_executable=arguments.python_relative_executable,
    )
    report = run_executable_functional_sensitivity(
        source_manifest_path=arguments.source_live_root / "artifact-manifest.json",
        output_dir=arguments.output_dir,
        cases=cases,
        executor=executor,
        command_argv=tuple(sys.argv if argv is None else [Path(__file__).name, *argv]),
        frozen_input_plan=plan,
    )
    print(_canonical(report), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

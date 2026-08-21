from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from collections import Counter
from dataclasses import replace
from pathlib import Path

import pytest

from secaware.canonical import canonical_sha256
from secaware.exploratory import executable_functional_sensitivity as sensitivity_module
from secaware.exploratory.artifact_integrity import (
    verify_closed_manifest,
    write_closed_manifest_atomic,
)
from secaware.exploratory.executable_functional_sensitivity import (
    ArmArtifactBinding,
    ExecutableSensitivityCase,
    ExecutorPolicy,
    FixtureInfrastructureError,
    FixtureInvocation,
    FrozenFunctionalContractBinding,
    GtfFastaAppendCliAdapter,
    IsolatedSubprocessExecutorV1,
    LocalCommandEvent,
    LocalExecutionObservation,
    PdfPdftotextBagOfWordsAdapter,
    SlurmSacctSqueueAdapter,
    SQLiteMetadataPragmaAdapter,
    VirtualCommandSpec,
    _isolated_worker_config,
    read_frozen_bag_of_words,
    run_executable_functional_sensitivity,
)
from secaware.functional_judge.schema import (
    FunctionalAuditStatus,
    FunctionalJudgeability,
    FunctionalRequirementRecord,
    TaskFunctionalContractRecord,
)
from secaware.oracle.runner import AnalyzerProcessResult
from secaware.pipeline.artifact import sha256_file

ADAPTERS = (
    GtfFastaAppendCliAdapter(),
    SQLiteMetadataPragmaAdapter(),
    PdfPdftotextBagOfWordsAdapter(),
    SlurmSacctSqueueAdapter(),
)


class FixtureTestExecutor:
    def __init__(self, *, failures: frozenset[str] = frozenset()) -> None:
        self.failures = failures
        self.calls: list[FixtureInvocation] = []
        self.policy = ExecutorPolicy(
            executor_id="non-executing-fixture-test-double-v1",
            mode="test_double",
            executes_generated_code=False,
            executes_in_main_process=False,
            timeout_seconds=5,
            isolated_subprocess=False,
            temporary_workspace=True,
            minimal_environment=True,
            virtual_commands_only=True,
            old_root_exposed=False,
            namespace_isolation_enforced=False,
            network_isolation_enforced=False,
            supported_adapter_ids=tuple(adapter.adapter_id for adapter in ADAPTERS),
        )

    def execute(self, invocation: FixtureInvocation) -> LocalExecutionObservation:
        self.calls.append(invocation)
        if invocation.adapter_id == GtfFastaAppendCliAdapter.adapter_id:
            if invocation.arm.assignment_id not in self.failures:
                for target, parameter in zip(
                    invocation.arguments,
                    ("predefined_gtf", "predefined_fasta"),
                    strict=True,
                ):
                    target_path = invocation.workspace / target
                    source_path = invocation.workspace / str(
                        invocation.fixture_parameters[parameter]
                    )
                    target_path.write_bytes(target_path.read_bytes() + source_path.read_bytes())
            events = tuple(
                LocalCommandEvent(
                    command_id=spec.command_id,
                    argv=(spec.argv0, spec.required_argument),
                    returncode=0,
                    stdout_target=(
                        "inputs/current.gtf"
                        if spec.command_id == "cat_gtf"
                        else "inputs/current.fasta"
                    ),
                    stdout_mode="ab",
                )
                for spec in invocation.virtual_commands
            )
            return LocalExecutionObservation(returncode=0, command_events=events)

        if invocation.adapter_id == SQLiteMetadataPragmaAdapter.adapter_id:
            if invocation.arm.assignment_id in self.failures:
                raise sqlite3.OperationalError('near "?": syntax error')
            database = invocation.workspace / invocation.arguments[0]
            with sqlite3.connect(database) as connection:
                columns = list(connection.execute('PRAGMA table_info("sample_records")'))
                indexes = list(connection.execute('PRAGMA index_list("sample_records")'))
            return LocalExecutionObservation(
                returncode=0,
                return_value=(columns, indexes),
                sqlite_statements=(
                    'PRAGMA table_info("sample_records")',
                    'PRAGMA index_list("sample_records")',
                ),
            )

        if invocation.adapter_id == PdfPdftotextBagOfWordsAdapter.adapter_id:
            output = invocation.workspace / invocation.arguments[1]
            output.write_text("alpha: 2\nbeta: 2\ngamma: 1\n", encoding="utf-8")
            return LocalExecutionObservation(
                returncode=0,
                command_events=(
                    LocalCommandEvent(
                        command_id="pdftotext_stdout",
                        argv=("pdftotext", "input.pdf", "-"),
                        returncode=0,
                    ),
                ),
            )

        if invocation.adapter_id == SlurmSacctSqueueAdapter.adapter_id:
            if invocation.arm.assignment_id in self.failures:
                return LocalExecutionObservation(
                    returncode=0,
                    return_value=None,
                    logs=("job is RUNNING",),
                    command_events=(
                        LocalCommandEvent(
                            command_id="squeue",
                            argv=("squeue", "-j", invocation.arguments[0]),
                            returncode=0,
                        ),
                    ),
                )
            return LocalExecutionObservation(
                returncode=0,
                return_value={"exit_code": "7:0"},
                logs=(f"job {invocation.arguments[0]} state COMPLETED",),
                command_events=(
                    LocalCommandEvent(
                        command_id="sacct_state_exit",
                        argv=("sacct", "-j", invocation.arguments[0]),
                        returncode=0,
                    ),
                ),
            )
        raise AssertionError("uncontrolled adapter reached the test executor")


class PdfInputOnlyPdftotextExecutor(FixtureTestExecutor):
    """Model real ``pdftotext input.pdf`` semantics: file output, empty stdout."""

    def execute(self, invocation: FixtureInvocation) -> LocalExecutionObservation:
        if invocation.adapter_id != PdfPdftotextBagOfWordsAdapter.adapter_id:
            return super().execute(invocation)
        self.calls.append(invocation)
        (invocation.workspace / "input.txt").write_text(
            "alpha beta beta gamma alpha\n",
            encoding="utf-8",
        )
        return LocalExecutionObservation(
            returncode=0,
            stdout=b"",
            command_events=(
                LocalCommandEvent(
                    command_id="pdftotext_default_file",
                    argv=("pdftotext", "input.pdf"),
                    returncode=0,
                    file_writes=("input.txt",),
                ),
            ),
        )


def _source_fixture(
    tmp_path: Path,
    adapters: tuple[object, ...] = ADAPTERS,
) -> tuple[Path, tuple[ExecutableSensitivityCase, ...]]:
    source = tmp_path / "frozen-live-root"
    source.mkdir()
    cases: list[ExecutableSensitivityCase] = []
    for task_number, adapter in enumerate(adapters, start=1):
        task_id = f"task-{task_number}-{adapter.family}"  # type: ignore[attr-defined]
        arms: list[ArmArtifactBinding] = []
        for arm_role in ("target_patch", "noop_rewrite"):
            assignment_id = f"assignment-{task_number}-{arm_role}"
            relative = Path("units") / assignment_id / "candidate.py"
            candidate = source / relative
            candidate.parent.mkdir(parents=True)
            code = f"# frozen {task_id} {arm_role}\n".encode()
            candidate.write_bytes(code)
            digest = hashlib.sha256(code).hexdigest()
            arms.append(
                ArmArtifactBinding(
                    assignment_id=assignment_id,
                    task_id=task_id,
                    arm_role=arm_role,  # type: ignore[arg-type]
                    artifact_relative_path=relative.as_posix(),
                    artifact_sha256=digest,
                    code_sha256=digest,
                )
            )
        prompt = f"Implement the frozen executable contract for {task_id}."
        requirements = tuple(
            FunctionalRequirementRecord(
                requirement_id=rule.requirement_id,
                kind="behavior",
                criterion=f"Satisfy frozen requirement {rule.requirement_id}.",
                prompt_evidence_quote="Implement the frozen executable contract",
            )
            for rule in adapter.requirement_rules  # type: ignore[attr-defined]
        )
        contract = TaskFunctionalContractRecord.from_content(
            task_id=task_id,
            source_prompt_id=f"prompt-{task_number}",
            source_prompt_sha256=hashlib.sha256(prompt.encode()).hexdigest(),
            language="python",
            judgeability=FunctionalJudgeability.EXECUTABLE,
            requirements=requirements,
            environment_dependencies=(),
            audit_pass_ids=("A",),
            audit_status=FunctionalAuditStatus.RESOLVED,
            auditor_kind="CODEX",
            audit_evidence_sha256="a" * 64,
        )
        contract_relative = Path("contracts") / f"{task_id}.jsonl"
        contract_path = source / contract_relative
        contract_path.parent.mkdir(parents=True, exist_ok=True)
        contract_path.write_text(
            json.dumps(
                contract.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        cases.append(
            ExecutableSensitivityCase(
                task_id=task_id,
                family=adapter.family,  # type: ignore[attr-defined]
                adapter=adapter,  # type: ignore[arg-type]
                arms=(arms[0], arms[1]),
                functional_contract=FrozenFunctionalContractBinding(
                    task_id=task_id,
                    contract_id=contract.contract_id,
                    artifact_relative_path=contract_relative.as_posix(),
                    artifact_sha256=sha256_file(contract_path),
                    requirement_ids=tuple(item.requirement_id for item in requirements),
                ),
            )
        )
    write_closed_manifest_atomic(source, label="test frozen live root")
    return source / "artifact-manifest.json", tuple(cases)


def _tree_digests(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): sha256_file(path)
        for path in root.rglob("*")
        if path.is_file()
    }


def _json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert type(value) is dict
    return value


def _jsonl(path: Path) -> list[dict[str, object]]:
    result = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert all(type(item) is dict for item in result)
    return result


def test_four_adapters_publish_eight_closed_content_addressed_tune_cases(
    tmp_path: Path,
) -> None:
    source_manifest, cases = _source_fixture(tmp_path)
    source_before = _tree_digests(source_manifest.parent)
    output = tmp_path / "sensitivity-sidecar"
    executor = FixtureTestExecutor()

    report = run_executable_functional_sensitivity(
        source_manifest_path=source_manifest,
        output_dir=output,
        cases=cases,
        executor=executor,
        command_argv=("secaware-test", "executable-sensitivity"),
        allow_test_executor=True,
    )

    assert report["status"] == "EXECUTABLE_FUNCTIONAL_SENSITIVITY_COMPLETE"
    assert report["functional_variable"] == "Y_F^E"
    assert report["execution_performed"] is True
    assert report["scientific_claim_allowed"] is False
    assert report["official_artifact_replacement_allowed"] is False
    assert report["counts"] == {
        "tasks": 4,
        "assignments": 8,
        "target_assignments": 4,
        "noop_assignments": 4,
        "y_f_e_pass": 8,
        "y_f_e_fail": 0,
        "judge_tune_cases": 8,
        "functional_contracts": 4,
        "provider_calls": 0,
        "security_oracle_calls": 0,
    }
    assert len(executor.calls) == 8
    assert _tree_digests(source_manifest.parent) == source_before
    verify_closed_manifest(output / "artifact-manifest.json", label="test sidecar")

    rows = _jsonl(output / "judge-tune-cases.jsonl")
    contracts = _jsonl(output / "frozen-functional-contracts.jsonl")
    assert len(rows) == 8
    assert len(contracts) == 4
    assert [item["task_id"] for item in contracts] == sorted(item["task_id"] for item in contracts)
    contract_source_paths = {
        str(row["task_id"]): source_manifest.parent / str(row["functional_contract_source_path"])
        for row in rows
    }
    for contract in contracts:
        original = contract_source_paths[str(contract["task_id"])].read_bytes()
        copied = (
            json.dumps(
                contract,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        assert copied.rstrip(b"\r\n") == original.rstrip(b"\r\n")
    assert all(item["equivalence_group"] is None for item in rows)
    assert set(Counter(str(item["paired_group_id"]) for item in rows).values()) == {2}
    source_manifest_sha256 = sha256_file(source_manifest)
    overlay_manifest_sha256 = sha256_file(output / "overlay-evidence-manifest.json")
    for row in rows:
        assert type(row["y_f_e"]) is int and row["y_f_e"] == 1
        assert row["expected_status"] == "pass"
        assert row["split"] == "tune"
        assert str(row["paired_group_id"]).startswith("functional_pair_")
        assert row["source_root_manifest_sha256"] == source_manifest_sha256
        assert row["overlay_evidence_manifest_sha256"] == overlay_manifest_sha256
        assert row["functional_contract_id"].startswith("functional_contract_")
        assert row["functional_contract_source_path"].startswith("contracts/")
        assert row["functional_requirement_ids"]
        assert row["functional_requirement_ids_sha256"] == canonical_sha256(
            row["functional_requirement_ids"]
        )
        assert row["frozen_functional_contracts_path"] == ("frozen-functional-contracts.jsonl")
        assert row["frozen_functional_contracts_sha256"] == sha256_file(
            output / "frozen-functional-contracts.jsonl"
        )
        for path_field, digest_field in (
            ("code_path", "code_sha256"),
            ("measurement_path", "measurement_sha256"),
        ):
            relative = Path(str(row[path_field]))
            assert not relative.is_absolute()
            assert relative.as_posix() == row[path_field]
            assert sha256_file(output / relative) == row[digest_field]
        content = dict(row)
        case_id = content.pop("case_id")
        assert case_id == "judge_tune_case_" + canonical_sha256(content)

    first_measurement = _json(output / str(rows[0]["measurement_path"]))
    measurement_content = dict(first_measurement)
    measurement_id = measurement_content.pop("measurement_id")
    assert measurement_id == "executable_functional_measurement_" + canonical_sha256(
        measurement_content
    )
    assert first_measurement["functional_variable"] == "Y_F^E"
    assert first_measurement["execution_performed"] is True
    assert first_measurement["y_f_e"] == 1
    assert all(item["verdict"] == "met" for item in first_measurement["requirement_verdicts"])
    unit = (output / str(rows[0]["measurement_path"])).parent
    observation = _json(unit / "execution-observation.json")
    assert set(observation) >= {
        "returncode",
        "stdout",
        "stderr",
        "command_events",
        "network_calls",
        "unvirtualized_process_calls",
    }


def test_arm_label_swap_does_not_change_any_fixture_verdict(tmp_path: Path) -> None:
    source_manifest, cases = _source_fixture(tmp_path)
    swapped_cases = tuple(
        replace(
            case,
            arms=tuple(
                replace(
                    arm,
                    arm_role=("noop_rewrite" if arm.arm_role == "target_patch" else "target_patch"),
                )
                for arm in case.arms
            ),
        )
        for case in cases
    )
    normal_output = tmp_path / "normal-sidecar"
    swapped_output = tmp_path / "swapped-sidecar"

    run_executable_functional_sensitivity(
        source_manifest_path=source_manifest,
        output_dir=normal_output,
        cases=cases,
        executor=FixtureTestExecutor(),
        allow_test_executor=True,
    )
    run_executable_functional_sensitivity(
        source_manifest_path=source_manifest,
        output_dir=swapped_output,
        cases=swapped_cases,
        executor=FixtureTestExecutor(),
        allow_test_executor=True,
    )

    normal = {
        str(row["assignment_id"]): row["y_f_e"]
        for row in _jsonl(normal_output / "judge-tune-cases.jsonl")
    }
    swapped = {
        str(row["assignment_id"]): row["y_f_e"]
        for row in _jsonl(swapped_output / "judge-tune-cases.jsonl")
    }
    assert swapped == normal


def test_worker_config_is_exact_and_arm_outcome_blind(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    candidate = workspace / "candidate.py"
    candidate.write_text(
        "import json\n"
        "config=json.load(open('/fixture-src/executor-config.json'))\n"
        "def append_files(a,b):\n"
        "    return config.get('arm_role') or config.get('expected_status')\n",
        encoding="utf-8",
    )
    code_sha = sha256_file(candidate)
    base_arm = ArmArtifactBinding(
        assignment_id="assignment-target",
        task_id="task-1",
        arm_role="target_patch",
        artifact_relative_path="candidate.py",
        artifact_sha256=code_sha,
        code_sha256=code_sha,
    )
    command = VirtualCommandSpec(
        command_id="cat_gtf",
        argv0="cat",
        required_argument="path/to/pre_defined.gtf",
        required_arguments=("path/to/pre_defined.gtf",),
        forbidden_arguments=("--help",),
        required_argument_kind="workspace_path",
        positional_argument_count=1,
        file_writes=(("inputs/current.gtf", b"frozen\n"),),
        stdout=b"frozen\n",
    )

    def payload(
        arm: ArmArtifactBinding,
        *,
        empty_workspace: bool = False,
    ) -> dict[str, object]:
        invocation = FixtureInvocation(
            adapter_id=GtfFastaAppendCliAdapter.adapter_id,
            fixture_policy_sha256="a" * 64,
            arm=arm,
            candidate_path=candidate,
            workspace=workspace,
            entrypoint_protocol="function_two_paths_v1",
            arguments=("inputs/current.gtf", "inputs/current.fasta"),
            fixture_parameters={"expected_status": "pass", "answer": 7},
            virtual_commands=(command,),
        )
        return _isolated_worker_config(
            invocation,
            workspace=workspace,
            workspace_files=(
                ()
                if empty_workspace
                else ({"path": "inputs/current.gtf", "sha256": "b" * 64, "bytes": 1},)
            ),
            sandbox_bindings=("/runtime:ro", "/fixture-src:ro", "/work:tmpfs"),
            resource_limits=(("cpu_seconds", 2),),
        )

    target = payload(base_arm)
    noop = payload(replace(base_arm, assignment_id="assignment-noop", arm_role="noop_rewrite"))
    assert target == noop
    assert payload(base_arm, empty_workspace=True)["workspace_files"] == []
    assert set(target) == {
        "schema_version",
        "adapter_id",
        "fixture_policy_sha256",
        "candidate_relative_path",
        "arguments",
        "resource_limits",
        "workspace_files",
        "sandbox_bindings",
        "virtual_commands",
    }
    serialized = json.dumps(target, sort_keys=True)
    assert all(
        forbidden not in serialized
        for forbidden in (
            "assignment-target",
            "assignment-noop",
            "target_patch",
            "noop_rewrite",
            "expected_status",
            '"answer"',
        )
    )
    virtual = target["virtual_commands"][0]
    assert virtual["required_arguments"] == ["path/to/pre_defined.gtf"]
    assert virtual["forbidden_arguments"] == ["--help"]
    assert virtual["required_argument_kind"] == "workspace_path"
    assert virtual["file_writes"][0]["path"] == "inputs/current.gtf"


def test_pdf_input_only_pdftotext_semantics_fail_both_arms(tmp_path: Path) -> None:
    source_manifest, cases = _source_fixture(
        tmp_path,
        (PdfPdftotextBagOfWordsAdapter(),),
    )
    output = tmp_path / "pdf-input-only-sidecar"

    report = run_executable_functional_sensitivity(
        source_manifest_path=source_manifest,
        output_dir=output,
        cases=cases,
        executor=PdfInputOnlyPdftotextExecutor(),
        allow_test_executor=True,
    )

    assert report["counts"]["y_f_e_pass"] == 0
    assert report["counts"]["y_f_e_fail"] == 2
    rows = _jsonl(output / "judge-tune-cases.jsonl")
    assert {row["arm_role"] for row in rows} == {"target_patch", "noop_rewrite"}
    assert {row["y_f_e"] for row in rows} == {0}
    for row in rows:
        measurement = _json(output / str(row["measurement_path"]))
        verdicts = {
            item["requirement_id"]: item["verdict"] for item in measurement["requirement_verdicts"]
        }
        assert verdicts["req_2"] == "met"
        assert verdicts["req_3"] == "not_met"
        observation = _json(
            (output / str(row["measurement_path"])).parent / "execution-observation.json"
        )
        assert observation["stdout"] == {
            "bytes": 0,
            "sha256": hashlib.sha256(b"").hexdigest(),
            "available": True,
        }
        assert observation["command_events"][0]["argv"] == ["pdftotext", "input.pdf"]
        assert observation["command_events"][0]["file_writes"] == ["input.txt"]


@pytest.mark.parametrize(
    ("adapter", "failing_assignment", "failed_requirement"),
    (
        (GtfFastaAppendCliAdapter(), "assignment-1-target_patch", "req_2"),
        (SQLiteMetadataPragmaAdapter(), "assignment-1-target_patch", "req_03"),
        (SlurmSacctSqueueAdapter(), "assignment-1-target_patch", "req_05"),
    ),
)
def test_known_execution_failures_become_y_f_e_zero(
    tmp_path: Path,
    adapter: object,
    failing_assignment: str,
    failed_requirement: str,
) -> None:
    source_manifest, cases = _source_fixture(tmp_path, (adapter,))
    output = tmp_path / "sensitivity-sidecar"

    run_executable_functional_sensitivity(
        source_manifest_path=source_manifest,
        output_dir=output,
        cases=cases,
        executor=FixtureTestExecutor(failures=frozenset({failing_assignment})),
        allow_test_executor=True,
    )

    rows = _jsonl(output / "judge-tune-cases.jsonl")
    target = next(item for item in rows if item["assignment_id"] == failing_assignment)
    noop = next(item for item in rows if item["arm_role"] == "noop_rewrite")
    assert type(target["y_f_e"]) is int and target["y_f_e"] == 0
    assert target["expected_status"] == "fail"
    assert noop["y_f_e"] == 1
    measurement = _json(output / str(target["measurement_path"]))
    verdicts = {
        item["requirement_id"]: item["verdict"] for item in measurement["requirement_verdicts"]
    }
    assert verdicts[failed_requirement] == "not_met"
    verify_closed_manifest(output / "artifact-manifest.json", label="failed functional case")


@pytest.mark.parametrize(
    "content",
    (
        '{"alpha":2,"beta":1}',
        "term,count\nalpha,2\nbeta,1\n",
        "term\tcount\nalpha\t2\nbeta\t1\n",
        "alpha: 2\nbeta: 1\n",
    ),
)
def test_pdf_frozen_reader_accepts_equivalent_machine_readable_formats(
    tmp_path: Path,
    content: str,
) -> None:
    output = tmp_path / "bag.txt"
    output.write_text(content, encoding="utf-8")
    assert read_frozen_bag_of_words(output) == {"alpha": 2, "beta": 1}


def test_existing_output_is_rejected_before_source_or_executor_changes(
    tmp_path: Path,
) -> None:
    source_manifest, cases = _source_fixture(tmp_path)
    source_before = _tree_digests(source_manifest.parent)
    output = tmp_path / "sensitivity-sidecar"
    output.mkdir()
    marker = output / "owned-by-user.txt"
    marker.write_text("preserve", encoding="utf-8")
    executor = FixtureTestExecutor()

    with pytest.raises(FileExistsError):
        run_executable_functional_sensitivity(
            source_manifest_path=source_manifest,
            output_dir=output,
            cases=cases,
            executor=executor,
            allow_test_executor=True,
        )

    assert marker.read_text(encoding="utf-8") == "preserve"
    assert not executor.calls
    assert _tree_digests(source_manifest.parent) == source_before


def test_test_double_requires_explicit_authorization(tmp_path: Path) -> None:
    source_manifest, cases = _source_fixture(tmp_path, (GtfFastaAppendCliAdapter(),))
    output = tmp_path / "sensitivity-sidecar"

    with pytest.raises(ValueError, match="test-double executor is not authorized"):
        run_executable_functional_sensitivity(
            source_manifest_path=source_manifest,
            output_dir=output,
            cases=cases,
            executor=FixtureTestExecutor(),
        )

    assert not output.exists()


def test_runtime_extension_inventory_excludes_unloaded_tkinter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    python = runtime / "bin" / "python3"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"frozen-python")
    dynload = runtime / "lib" / "python3.12" / "lib-dynload"
    dynload.mkdir(parents=True)
    needed = dynload / "_sqlite3.cpython-312-x86_64-linux-gnu.so"
    needed.write_bytes(b"needed-extension")
    irrelevant = dynload / "_tkinter.cpython-312-x86_64-linux-gnu.so"
    irrelevant.write_bytes(b"would-have-a-missing-tcl-dependency")
    calls: list[tuple[str, ...]] = []

    def discover(argv: tuple[str, ...], **_kwargs: object) -> AnalyzerProcessResult:
        calls.append(argv)
        payload = {
            "extension_modules": [str(needed.resolve())],
            "runtime_root": str(runtime.resolve()),
            "schema_version": "1.0",
        }
        return AnalyzerProcessResult(
            returncode=0,
            stdout=sensitivity_module._canonical(payload),
            argv_sha256="0" * 64,
        )

    monkeypatch.setattr(sensitivity_module, "run_analyzer_process", discover)

    selected = sensitivity_module._discover_runtime_extension_modules(runtime, python)

    assert selected == (needed.resolve(),)
    assert irrelevant.resolve() not in selected
    assert len(calls) == 1
    assert calls[0][1:5] == ("-I", "-B", "-S", "-c")
    assert calls[0][-1] == str(runtime.resolve())
    assert sensitivity_module._FROZEN_CANDIDATE_RUNTIME_IMPORTS == ("collections", "re")


@pytest.mark.parametrize(
    "failure",
    (
        "discovery_failed",
        "invalid_json",
        "noncanonical_json",
        "relative",
        "escaped",
        "missing",
        "outside_dynload",
        "duplicate",
    ),
)
def test_runtime_extension_inventory_rejects_invalid_or_missing_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    runtime = tmp_path / "runtime"
    python = runtime / "bin" / "python3"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"frozen-python")
    dynload = runtime / "lib" / "python3.12" / "lib-dynload"
    dynload.mkdir(parents=True)
    needed = dynload / "_sqlite3.so"
    needed.write_bytes(b"needed-extension")
    escaped = tmp_path / "escaped.so"
    escaped.write_bytes(b"escaped-extension")
    outside_dynload = runtime / "lib" / "outside.so"
    outside_dynload.write_bytes(b"outside-dynload")

    modules = [str(needed.resolve())]
    if failure == "relative":
        modules = ["lib/python3.12/lib-dynload/_sqlite3.so"]
    elif failure == "escaped":
        modules = [str(escaped.resolve())]
    elif failure == "missing":
        modules = [str((dynload / "missing.so").resolve())]
    elif failure == "outside_dynload":
        modules = [str(outside_dynload.resolve())]
    elif failure == "duplicate":
        modules = [str(needed.resolve()), str(needed.resolve())]
    payload = {
        "extension_modules": modules,
        "runtime_root": str(runtime.resolve()),
        "schema_version": "1.0",
    }
    stdout = sensitivity_module._canonical(payload)
    returncode = 0
    if failure == "discovery_failed":
        returncode = 1
    elif failure == "invalid_json":
        stdout = b"not-json"
    elif failure == "noncanonical_json":
        stdout = json.dumps(payload).encode("utf-8")

    def discover(_argv: tuple[str, ...], **_kwargs: object) -> AnalyzerProcessResult:
        return AnalyzerProcessResult(
            returncode=returncode,
            stdout=stdout,
            argv_sha256="0" * 64,
        )

    monkeypatch.setattr(sensitivity_module, "run_analyzer_process", discover)

    with pytest.raises(ValueError, match="runtime (?:extension|import)|frozen Python"):
        sensitivity_module._discover_runtime_extension_modules(runtime, python)


def test_runtime_extension_inventory_may_be_empty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    python = runtime / "bin" / "python3"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"frozen-python")
    payload = {
        "extension_modules": [],
        "runtime_root": str(runtime.resolve()),
        "schema_version": "1.0",
    }

    monkeypatch.setattr(
        sensitivity_module,
        "run_analyzer_process",
        lambda *_args, **_kwargs: AnalyzerProcessResult(
            returncode=0,
            stdout=sensitivity_module._canonical(payload),
            argv_sha256="0" * 64,
        ),
    )

    assert sensitivity_module._discover_runtime_extension_modules(runtime, python) == ()


def test_dynamic_library_closure_inspects_only_selected_extensions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    python = runtime / "bin" / "python3"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"frozen-python")
    dynload = runtime / "lib" / "python3.12" / "lib-dynload"
    dynload.mkdir(parents=True)
    needed = dynload / "_sqlite3.so"
    needed.write_bytes(b"needed-extension")
    irrelevant = dynload / "_tkinter.so"
    irrelevant.write_bytes(b"missing-tcl-if-inspected")
    inspector = tmp_path / "ldd"
    inspector.write_bytes(b"frozen-ldd")
    loader = tmp_path / "ld-linux.so"
    loader.write_bytes(b"frozen-loader")
    calls: list[tuple[str, ...]] = []

    monkeypatch.setattr(
        sensitivity_module,
        "_dynamic_library_inspector_path",
        lambda: inspector,
    )
    monkeypatch.setattr(
        sensitivity_module,
        "_discover_runtime_extension_modules",
        lambda _runtime, _python: (needed,),
    )
    monkeypatch.setattr(
        sensitivity_module,
        "_external_dynamic_library_binding",
        lambda raw, _runtime: (
            raw.as_posix(),
            str(loader),
            sha256_file(loader),
        ),
    )

    def inspect(argv: tuple[str, ...], **_kwargs: object) -> AnalyzerProcessResult:
        calls.append(argv)
        stdout = (
            b"libtcl8.6.so => not found\n"
            if str(irrelevant) in argv
            else (
                b"/runtime/bin/python3:\n"
                b"/lib64/ld-linux-x86-64.so.2 (0x00007f00)\n"
                b"/runtime/lib/python3.12/lib-dynload/_sqlite3.so:\n"
                b"/lib64/ld-linux-x86-64.so.2 (0x00007f01)\n"
            )
        )
        return AnalyzerProcessResult(
            returncode=0,
            stdout=stdout,
            argv_sha256="0" * 64,
        )

    monkeypatch.setattr(sensitivity_module, "run_analyzer_process", inspect)

    selected_inspector, bindings = sensitivity_module._dynamic_library_closure(
        runtime,
        python,
    )

    assert selected_inspector == inspector
    assert calls == [(str(inspector), str(python), str(needed))]
    assert irrelevant.as_posix() not in calls[0]
    assert bindings == (("/lib64/ld-linux-x86-64.so.2", str(loader), sha256_file(loader)),)


def test_dynamic_library_closure_rejects_conflicting_duplicate_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "runtime"
    python = runtime / "bin" / "python3"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"frozen-python")
    needed = runtime / "lib" / "python3.12" / "lib-dynload" / "_sqlite3.so"
    needed.parent.mkdir(parents=True)
    needed.write_bytes(b"needed-extension")
    inspector = tmp_path / "ldd"
    inspector.write_bytes(b"frozen-ldd")
    first_loader = tmp_path / "first-ld-linux.so"
    first_loader.write_bytes(b"first-loader")
    second_loader = tmp_path / "second-ld-linux.so"
    second_loader.write_bytes(b"second-loader")
    bindings = iter(
        (
            (
                "/lib64/ld-linux-x86-64.so.2",
                str(first_loader),
                sha256_file(first_loader),
            ),
            (
                "/lib64/ld-linux-x86-64.so.2",
                str(second_loader),
                sha256_file(second_loader),
            ),
        )
    )
    monkeypatch.setattr(
        sensitivity_module,
        "_dynamic_library_inspector_path",
        lambda: inspector,
    )
    monkeypatch.setattr(
        sensitivity_module,
        "_discover_runtime_extension_modules",
        lambda _runtime, _python: (needed,),
    )
    monkeypatch.setattr(
        sensitivity_module,
        "_external_dynamic_library_binding",
        lambda _raw, _runtime: next(bindings),
    )
    monkeypatch.setattr(
        sensitivity_module,
        "run_analyzer_process",
        lambda *_args, **_kwargs: AnalyzerProcessResult(
            returncode=0,
            stdout=(
                b"/lib64/ld-linux-x86-64.so.2 (0x00007f00)\n"
                b"/lib64/ld-linux-x86-64.so.2 (0x00007f01)\n"
            ),
            argv_sha256="0" * 64,
        ),
    )

    with pytest.raises(ValueError, match="dynamic library closure failed validation"):
        sensitivity_module._dynamic_library_closure(runtime, python)


@pytest.mark.parametrize(
    ("returncode", "stdout"),
    (
        (1, b""),
        (0, b"libsqlite3.so => not found\n"),
    ),
)
def test_dynamic_library_closure_rejects_missing_selected_dependency(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    stdout: bytes,
) -> None:
    runtime = tmp_path / "runtime"
    python = runtime / "bin" / "python3"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"frozen-python")
    needed = runtime / "lib" / "python3.12" / "lib-dynload" / "_sqlite3.so"
    needed.parent.mkdir(parents=True)
    needed.write_bytes(b"needed-extension")
    inspector = tmp_path / "ldd"
    inspector.write_bytes(b"frozen-ldd")
    monkeypatch.setattr(
        sensitivity_module,
        "_dynamic_library_inspector_path",
        lambda: inspector,
    )
    monkeypatch.setattr(
        sensitivity_module,
        "_discover_runtime_extension_modules",
        lambda _runtime, _python: (needed,),
    )
    monkeypatch.setattr(
        sensitivity_module,
        "run_analyzer_process",
        lambda *_args, **_kwargs: AnalyzerProcessResult(
            returncode=returncode,
            stdout=stdout,
            argv_sha256="0" * 64,
        ),
    )

    with pytest.raises(ValueError, match="dynamic library closure"):
        sensitivity_module._dynamic_library_closure(runtime, python)


@pytest.mark.parametrize("mutated_component", ("bwrap", "python", "runtime", "ldd", "library"))
def test_frozen_runtime_reattestation_rejects_post_init_mutation(
    tmp_path: Path,
    mutated_component: str,
) -> None:
    runtime = tmp_path / "runtime"
    python = runtime / "bin" / "python3"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"frozen-python")
    bwrap = tmp_path / "bwrap"
    bwrap.write_bytes(b"frozen-bwrap")
    inspector = tmp_path / "ldd"
    inspector.write_bytes(b"frozen-ldd")
    library = tmp_path / "libfixture.so"
    library.write_bytes(b"frozen-library")
    executor = object.__new__(IsolatedSubprocessExecutorV1)
    executor._bwrap = bwrap
    executor._runtime = runtime
    executor._python_relative = Path("bin/python3")
    executor._library_inspector = inspector
    executor._dynamic_libraries = (("/lib/libfixture.so", str(library), sha256_file(library)),)
    executor.policy = ExecutorPolicy(
        executor_id="runtime-reattestation-fixture",
        mode="isolated_subprocess_v1",
        executes_generated_code=True,
        executes_in_main_process=False,
        timeout_seconds=1,
        isolated_subprocess=True,
        temporary_workspace=True,
        minimal_environment=True,
        virtual_commands_only=True,
        old_root_exposed=False,
        namespace_isolation_enforced=True,
        network_isolation_enforced=True,
        supported_adapter_ids=(GtfFastaAppendCliAdapter.adapter_id,),
        sandbox_backend_path=str(bwrap),
        sandbox_backend_sha256=sha256_file(bwrap),
        python_runtime_root=str(runtime),
        python_runtime_sha256=sensitivity_module._runtime_tree_sha256(runtime),
        python_executable_sha256=sha256_file(python),
        dynamic_library_inspector_path=str(inspector),
        dynamic_library_inspector_sha256=sha256_file(inspector),
        dynamic_library_bindings=executor._dynamic_libraries,
    )
    executor.verify_frozen_runtime()

    mutated_path = {
        "bwrap": bwrap,
        "python": python,
        "runtime": runtime / "new-runtime-file",
        "ldd": inspector,
        "library": library,
    }[mutated_component]
    mutated_path.write_bytes(b"mutated")

    with pytest.raises(FixtureInfrastructureError, match="runtime attestation failed"):
        executor.verify_frozen_runtime()


def test_source_mutation_is_detected_and_failure_root_is_closed(tmp_path: Path) -> None:
    source_manifest, cases = _source_fixture(tmp_path, (GtfFastaAppendCliAdapter(),))
    output = tmp_path / "sensitivity-sidecar"
    executor = FixtureTestExecutor()
    original_execute = executor.execute

    def mutating_execute(invocation: FixtureInvocation) -> LocalExecutionObservation:
        source_manifest.write_text("{}\n", encoding="utf-8")
        return original_execute(invocation)

    executor.execute = mutating_execute  # type: ignore[method-assign]

    with pytest.raises(ValueError, match="frozen source manifest changed"):
        run_executable_functional_sensitivity(
            source_manifest_path=source_manifest,
            output_dir=output,
            cases=cases,
            executor=executor,
            allow_test_executor=True,
        )

    failure = _json(output / "failure.json")
    assert failure["status"] == "EXECUTABLE_FUNCTIONAL_SENSITIVITY_FAILED"
    verify_closed_manifest(output / "artifact-manifest.json", label="failed sidecar")


_BWRAP = Path(os.environ.get("SECAWARE_TEST_BWRAP", "/usr/bin/bwrap"))
_PYTHON_RUNTIME = Path(
    os.environ.get(
        "SECAWARE_TEST_PYTHON_RUNTIME",
        "/home/ubuntu/.local/share/uv/python/cpython-3.12.12-linux-x86_64-gnu",
    )
)


@pytest.mark.skipif(
    os.name != "posix" or not _BWRAP.is_file() or not _PYTHON_RUNTIME.is_dir(),
    reason="requires the frozen Linux Bubblewrap/Python runtime",
)
def test_linux_bubblewrap_executor_runs_one_controlled_pair(tmp_path: Path) -> None:
    source_manifest, cases = _source_fixture(tmp_path, (GtfFastaAppendCliAdapter(),))
    code = (
        b"import subprocess\n"
        b"def append_files(gtf_file, fasta_file):\n"
        b"    pairs = ((gtf_file, 'path/to/pre_defined.gtf'), "
        b"(fasta_file, 'path/to/pre_defined.fasta'))\n"
        b"    for target, source in pairs:\n"
        b"        with open(target, 'ab') as output:\n"
        b"            subprocess.run(['cat', source], stdout=output, check=True)\n"
    )
    digest = hashlib.sha256(code).hexdigest()
    rebound_arms: list[ArmArtifactBinding] = []
    for arm in cases[0].arms:
        artifact = source_manifest.parent / arm.artifact_relative_path
        artifact.write_bytes(code)
        rebound_arms.append(
            ArmArtifactBinding(
                assignment_id=arm.assignment_id,
                task_id=arm.task_id,
                arm_role=arm.arm_role,
                artifact_relative_path=arm.artifact_relative_path,
                artifact_sha256=digest,
                code_sha256=digest,
            )
        )
    source_manifest.unlink()
    write_closed_manifest_atomic(source_manifest.parent, label="Bubblewrap integration source")
    rebound_case = ExecutableSensitivityCase(
        task_id=cases[0].task_id,
        family=cases[0].family,
        adapter=cases[0].adapter,
        arms=(rebound_arms[0], rebound_arms[1]),
        functional_contract=cases[0].functional_contract,
    )
    executor = IsolatedSubprocessExecutorV1(
        bwrap_executable=_BWRAP,
        python_runtime_root=_PYTHON_RUNTIME,
    )
    output = tmp_path / "bubblewrap-sidecar"

    report = run_executable_functional_sensitivity(
        source_manifest_path=source_manifest,
        output_dir=output,
        cases=(rebound_case,),
        executor=executor,
    )

    assert report["counts"]["assignments"] == 2
    assert report["counts"]["y_f_e_pass"] == 2
    protocol = _json(output / "protocol.json")
    assert protocol["executor_policy"]["sandbox_backend"] == "bubblewrap_v1"
    assert protocol["sandbox_limitations"] == []
    verify_closed_manifest(output / "artifact-manifest.json", label="Bubblewrap sidecar")


@pytest.mark.skipif(
    os.name != "posix" or not _BWRAP.is_file() or not _PYTHON_RUNTIME.is_dir(),
    reason="requires the frozen Linux Bubblewrap/Python runtime",
)
def test_linux_bubblewrap_executor_accepts_slurm_empty_workspace_closure(
    tmp_path: Path,
) -> None:
    source_manifest, cases = _source_fixture(tmp_path, (SlurmSacctSqueueAdapter(),))
    code = (
        b"import subprocess\n"
        b"def get_job_exit_code(job_id):\n"
        b"    result = subprocess.run(['sacct', '-j', job_id], "
        b"capture_output=True, text=True, check=True)\n"
        b"    state, exit_code = result.stdout.strip().split('|')\n"
        b"    print(f'job {job_id} state {state}')\n"
        b"    return int(exit_code.split(':')[0])\n"
    )
    digest = hashlib.sha256(code).hexdigest()
    rebound_arms: list[ArmArtifactBinding] = []
    for arm in cases[0].arms:
        artifact = source_manifest.parent / arm.artifact_relative_path
        artifact.write_bytes(code)
        rebound_arms.append(
            replace(
                arm,
                artifact_sha256=digest,
                code_sha256=digest,
            )
        )
    source_manifest.unlink()
    write_closed_manifest_atomic(
        source_manifest.parent,
        label="Bubblewrap Slurm empty-closure integration source",
    )
    rebound_case = replace(
        cases[0],
        arms=(rebound_arms[0], rebound_arms[1]),
    )
    output = tmp_path / "bubblewrap-slurm-sidecar"

    report = run_executable_functional_sensitivity(
        source_manifest_path=source_manifest,
        output_dir=output,
        cases=(rebound_case,),
        executor=IsolatedSubprocessExecutorV1(
            bwrap_executable=_BWRAP,
            python_runtime_root=_PYTHON_RUNTIME,
        ),
    )

    assert report["counts"]["assignments"] == 2
    assert report["counts"]["y_f_e_pass"] == 2
    for observation_path in output.glob("units/*/execution-observation.json"):
        observation = _json(observation_path)
        assert observation["command_events"][0]["command_id"] == "sacct_state_exit"
        assert observation["return_value"] == 7
    verify_closed_manifest(
        output / "artifact-manifest.json",
        label="Bubblewrap Slurm sidecar",
    )

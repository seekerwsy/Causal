from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

import pytest

from secaware.config import (
    AppConfig,
    DataConfig,
    FunctionalJudgeConfig,
    FunctionalJudgeLLMConfig,
    GenerationConfig,
    InterventionConfig,
    RunConfig,
    TSGConfig,
    write_resolved_config,
)
from secaware.exploratory.artifact_integrity import write_closed_manifest_atomic
from secaware.exploratory.dev_canary_analysis import analyze_dev_canary
from secaware.exploratory.gate_c_live import _json_value, _profile_decision_payload
from secaware.exploratory.independent_validation_run import _verify_manifest
from secaware.functional_judge.factory import create_functional_judge
from secaware.functional_judge.judge import _parse_response, _request_payload
from secaware.functional_judge.schema import (
    FunctionalAuditStatus,
    FunctionalJudgeability,
    FunctionalJudgePassRecord,
    FunctionalRequirementRecord,
    ProgramFunctionalOutcomeRecord,
    TaskFunctionalContractRecord,
)
from secaware.generation.request_planner import plan_confirmation_requests
from secaware.generation.result_importer import canonical_generated_code_from_request
from secaware.llm.structured_transport import canonical_request_bytes
from secaware.oracle.aggregator import OracleCodeAnalysis
from secaware.oracle.policy import load_policy_bundle
from secaware.oracle.profile_decision import extract_python_mechanism_trace
from secaware.pipeline.artifact import canonical_sha256, sha256_file
from secaware.schema.experiments import (
    ArmRole,
    AssignmentExecutionRecord,
    AssignmentExecutionStatus,
    AssignmentRecord,
    ExperimentalUnit,
    InterventionExecutorKind,
    PromptVariantRecord,
)
from secaware.schema.features import PromptExtractorBackend
from secaware.schema.generation import GenerationProvenance, provider_provenance_sha256
from secaware.schema.oracle import AnalyzerProvenanceRecord, OracleEvaluability, SecurityLabel
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
    path = root / "artifact-manifest.json"
    if path.exists():
        path.unlink()
    write_closed_manifest_atomic(root, label="test fixture")


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _assignment_and_variant(
    *, task_id: str, arm: ArmRole, seed_slot: int
) -> tuple[AssignmentRecord, PromptVariantRecord]:
    hypothesis_id = "hypothesis_" + _sha(task_id + ":hypothesis")
    target_spec_id = "target_" + _sha(task_id + ":target")
    protocol_id = "arm_protocol_" + _sha(task_id + ":protocol")
    target_instance_id = "target_instance_" + _sha(task_id + ":target-instance")
    protocol_instance_id = "protocol_instance_" + _sha(task_id + ":protocol-instance")
    prompt = f"Implement the required Python function for {task_id}."
    variant = PromptVariantRecord.from_content(
        task_id=task_id,
        source_prompt_id=f"prompt-{task_id}",
        language="python",
        variant_prompt_id="variant_prompt_" + _sha(task_id + arm.value),
        hypothesis_id=hypothesis_id,
        target_spec_id=target_spec_id,
        target_instance_id=target_instance_id,
        arm_protocol_id=protocol_id,
        protocol_instance_id=protocol_instance_id,
        arm_role=arm,
        prompt_sha256=_sha(prompt),
        prompt_text=prompt,
        proposal_id="proposal_" + _sha(task_id + ":proposal"),
        graph_id="graph_" + _sha(task_id + ":graph"),
        delta_id="delta_" + _sha(task_id + arm.value + ":delta"),
        executor_policy_sha256="4" * 64,
        extractor_policy_sha256="5" * 64,
        length_match_id=None,
    )
    unit = ExperimentalUnit(
        task_id=task_id,
        hypothesis_id=hypothesis_id,
        target_spec_id=target_spec_id,
        model_id="model-dev",
        seed_slot=seed_slot,
    )
    assignment = AssignmentRecord.from_content(
        block_id=AssignmentRecord.block_id_from_key(
            task_id,
            hypothesis_id,
            target_spec_id,
            protocol_id,
            "model-dev",
        ),
        experimental_unit=unit,
        target_spec_id=target_spec_id,
        target_instance_id=target_instance_id,
        arm_protocol_id=protocol_id,
        protocol_instance_id=protocol_instance_id,
        variant_id=variant.variant_id,
        arm_role=arm,
        seed_id=100 + seed_slot,
        rng_version="sha256-rejection-fisher-yates-v1",
        randomization_plan_sha256="5" * 64,
    )
    return assignment, variant


def _contract(task_id: str) -> TaskFunctionalContractRecord:
    prompt = f"Implement the required Python function for {task_id}."
    return TaskFunctionalContractRecord.from_content(
        task_id=task_id,
        source_prompt_id=f"prompt-{task_id}",
        source_prompt_sha256=_sha(prompt),
        language="python",
        judgeability=FunctionalJudgeability.EXECUTABLE,
        requirements=(
            FunctionalRequirementRecord(
                requirement_id="req_behavior",
                kind="behavior",
                criterion="The requested function is implemented.",
                prompt_evidence_quote="Implement the required Python function",
            ),
        ),
        environment_dependencies=(),
        audit_pass_ids=("A",),
        audit_status=FunctionalAuditStatus.RESOLVED,
        auditor_kind="CODEX",
        audit_evidence_sha256="6" * 64,
    )


def _generation_config(task_count: int) -> GenerationConfig:
    return GenerationConfig(
        provider="mock",
        models=["model-dev"],
        seeds=[1],
        confirmation_seeds=[100, 101],
        confirmation_max_requests=task_count * 2,
        confirmation_max_total_provider_attempts=task_count * 2,
    )


def _app_config() -> AppConfig:
    return AppConfig(
        run=RunConfig(name="dev-canary-fixture", output_dir="runs/fixture"),
        data=DataConfig(
            prompts_path="fixture-prompts.jsonl",
            prompt_attestations_path="fixture-attestations.jsonl",
            task_functional_contracts_path="fixture-contracts.jsonl",
        ),
        tsg=TSGConfig(
            prompt_extractor=PromptExtractorBackend.DETERMINISTIC_CATALOG_V1,
            llm=None,
        ),
        intervention=InterventionConfig(
            executor=InterventionExecutorKind.DETERMINISTIC,
            llm=None,
        ),
        functional_judge=FunctionalJudgeConfig(
            enabled=True,
            llm=FunctionalJudgeLLMConfig(
                model_id="judge-model",
                base_url="https://judge.invalid/v1",
                api_key_env="TEST_JUDGE_API_KEY",
                timeout_seconds=30.0,
                max_attempts=1,
                max_response_bytes=65_536,
                temperature=0.0,
                top_p=1.0,
                seed=None,
                enable_thinking=False,
            ),
            mode="single_pass",
            pass_seeds=(73_001,),
        ),
    )


class _NeverCalledTransport:
    def complete(self, _request: bytes, _policy: object) -> bytes:
        raise AssertionError("fixture Judge transport must not be called")


def _code(cwe: str, arm: ArmRole) -> str:
    secure = arm is ArmRole.TARGET_PATCH
    if cwe == "CWE-78":
        return (
            "import subprocess\n\ndef run(package):\n"
            '    return subprocess.run(["rpm", "-q", package], shell=False)\n'
            if secure
            else (
                "import subprocess\n\ndef run(package):\n"
                '    return subprocess.run(f"rpm -q {package}", shell=True)\n'
            )
        )
    return (
        "def remove_user(username, cursor):\n"
        '    return cursor.execute("DELETE FROM users WHERE username = ?", (username,))\n'
        if secure
        else (
            "def remove_user(username, cursor):\n"
            '    return cursor.execute(f"DELETE FROM users WHERE username = {username}")\n'
        )
    )


_POLICY_LOCK = Path(__file__).parents[1] / "policies" / "oracle" / "python-v2" / "policy.lock.json"


def _write_transport(
    root: Path,
    *,
    request: bytes,
    response: bytes,
    request_id: str | None,
    functional: bool,
) -> None:
    root.mkdir(parents=True)
    (root / "request.json").write_bytes(request + b"\n")
    (root / "response.json").write_bytes(response + b"\n")
    _write_json(
        root / "transport.json",
        (
            {
                "schema_version": "1.0",
                "request_sha256": hashlib.sha256(request).hexdigest(),
                "response_sha256": hashlib.sha256(response).hexdigest(),
                "attempts": 1,
            }
            if functional
            else {
                "schema_version": "1.0",
                "request_id": request_id,
                "attempt": 1,
                "request_sha256": hashlib.sha256(request).hexdigest(),
                "response_sha256": hashlib.sha256(response).hexdigest(),
                "transport_error": False,
            }
        ),
    )


def _write_analyzer_transport(unit: Path) -> None:
    root = unit / "oracle-analyzer-transport"
    root.mkdir()
    for index, analyzer in enumerate(("semgrep", "bandit"), start=1):
        call = root / f"call-{index:03d}-{analyzer}"
        call.mkdir()
        stdout = _canonical({"analyzer": analyzer, "results": []})
        (call / "stdout.bin").write_bytes(stdout)
        _write_json(
            call / "result.json",
            {
                "schema_version": "1.0",
                "analyzer": analyzer,
                "returncode": 0,
                "argv_sha256": str(index) * 64,
                "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                "stdout_bytes": len(stdout),
            },
        )
    _write_json(
        root / "session.json",
        {"schema_version": "1.0", "calls": 2, "coordinate_blind": True},
    )


def _fixture(
    tmp_path: Path,
    *,
    task_count: int = 2,
    include_terminal_no_code: bool = True,
    remaining_attempt: int = 1,
) -> tuple[Path, Path]:
    plan_dir = tmp_path / "plan"
    live_dir = tmp_path / "live"
    plan_dir.mkdir()
    live_dir.mkdir()
    if task_count not in {2, 12} or remaining_attempt < 1:
        raise ValueError("test fixture task count")
    app_config = _app_config()
    write_resolved_config(app_config, live_dir / "effective-app-config.yaml")
    evaluator_policy_sha256 = create_functional_judge(
        app_config,
        transport_factory=lambda **_kwargs: _NeverCalledTransport(),
    ).policy_sha256
    per_cwe = task_count // 2
    tasks = [(f"task-cwe78-{index:02d}", "CWE-78") for index in range(per_cwe)] + [
        (f"task-cwe89-{index:02d}", "CWE-89") for index in range(per_cwe)
    ]
    pairs = [
        _assignment_and_variant(task_id=task_id, arm=arm, seed_slot=seed_slot)
        for task_id, _cwe in tasks
        for seed_slot, arm in enumerate((ArmRole.TARGET_PATCH, ArmRole.NOOP_REWRITE))
    ]
    assignments = [item[0] for item in pairs]
    variants = [item[1] for item in pairs]
    requests = plan_confirmation_requests(
        assignments,
        variants,
        _generation_config(task_count),
    )
    request_by_assignment = {str(item.assignment_id): item for item in requests}
    contracts = [_contract(task_id) for task_id, _cwe in tasks]
    contract_by_task = {item.task_id: item for item in contracts}
    cwe_by_task = dict(tasks)
    profiles = {
        item.cwe: item
        for item in load_policy_bundle(_POLICY_LOCK).coverage_profiles
        if item.profile_id
        in {
            "python.cwe78.function_parameter_subprocess.v2",
            "python.cwe89.function_parameter_sqlite_query.v2",
        }
    }
    coverage_rows = [
        {
            "schema_version": "1.0",
            "task_id": task_id,
            "prompt_id": contract_by_task[task_id].source_prompt_id,
            "cwe": cwe,
            "oracle_profile_id": profiles[cwe].profile_id,
            "zero_finding_interpretation": "profile_scoped_decision",
            "zero_finding_supported": True,
            "decision_backend": "python_ast_mechanism_v1",
            "analyzer_rule_ids": list(profiles[cwe].analyzer_rule_ids),
        }
        for task_id, cwe in tasks
    ]
    coverage_by_task = {str(item["task_id"]): item for item in coverage_rows}
    _write_jsonl(
        plan_dir / "assignments.jsonl",
        [item.model_dump(mode="json") for item in assignments],
    )
    _write_jsonl(
        plan_dir / "generation-requests.jsonl",
        [item.model_dump(mode="json") for item in requests],
    )
    _write_jsonl(
        plan_dir / "task-functional-contracts.jsonl",
        [item.model_dump(mode="json") for item in contracts],
    )
    _write_jsonl(
        plan_dir / "oracle-coverage.jsonl",
        coverage_rows,
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
                "assignments": task_count * 2,
                "generation_requests": task_count * 2,
                "independent_tasks": task_count,
            },
        },
    )
    _manifest(plan_dir)

    assignment_ids = []
    for assignment in assignments:
        assignment_ids.append(assignment.assignment_id)
        unit = live_dir / "units" / assignment.assignment_id
        unit.mkdir(parents=True)
        task_id = assignment.experimental_unit.task_id
        cwe = cwe_by_task[task_id]
        request = request_by_assignment[assignment.assignment_id]
        contract = contract_by_task[task_id]
        coverage = coverage_by_task[task_id]
        _write_jsonl(unit / "assignment.jsonl", [assignment.model_dump(mode="json")])
        _write_jsonl(unit / "generation-request.jsonl", [request.model_dump(mode="json")])
        _write_jsonl(unit / "functional-contract.jsonl", [contract.model_dump(mode="json")])
        _write_json(unit / "oracle-coverage.json", coverage)
        terminal = (
            include_terminal_no_code
            and task_id == "task-cwe89-00"
            and assignment.arm_role is ArmRole.TARGET_PATCH
        )
        provenance = GenerationProvenance(
            producer="fixture-provider",
            producer_version="1",
            source_batch_id="fixture-batch",
        )
        provider_result_sha256 = "a" * 64
        provider_usage_sha256 = "b" * 64
        provider_runtime_sha256 = "c" * 64
        provider_policy_sha256 = "d" * 64
        if terminal:
            code = None
            execution = AssignmentExecutionRecord.from_content(
                assignment_id=assignment.assignment_id,
                request_id=request.request_id,
                status=AssignmentExecutionStatus.TERMINAL_NO_CODE,
                provider_result_sha256=provider_result_sha256,
                provider_provenance_sha256=provider_provenance_sha256(provenance),
                provider_runtime_sha256=provider_runtime_sha256,
                provider_policy_sha256=provider_policy_sha256,
                usage_sha256=provider_usage_sha256,
                attempt_count=1,
                code_id=None,
                code_sha256=None,
                terminal_reason="content_filter",
            )
        else:
            code = canonical_generated_code_from_request(
                request,
                _code(cwe, assignment.arm_role),
                provenance,
                provider_result_sha256=provider_result_sha256,
                provider_usage_sha256=provider_usage_sha256,
                provider_runtime_sha256=provider_runtime_sha256,
                provider_policy_sha256=provider_policy_sha256,
                provider_attempt_count=1,
            )
            execution = AssignmentExecutionRecord.from_content(
                assignment_id=assignment.assignment_id,
                request_id=request.request_id,
                status=AssignmentExecutionStatus.GENERATED,
                provider_result_sha256=provider_result_sha256,
                provider_provenance_sha256=provider_provenance_sha256(provenance),
                provider_runtime_sha256=provider_runtime_sha256,
                provider_policy_sha256=provider_policy_sha256,
                usage_sha256=provider_usage_sha256,
                attempt_count=1,
                code_id=code.code_id,
                code_sha256=code.code_sha256,
                terminal_reason=None,
            )
        _write_jsonl(unit / "assignment-execution.jsonl", [execution.model_dump(mode="json")])
        _write_jsonl(
            unit / "generated-code.jsonl",
            [] if code is None else [code.model_dump(mode="json")],
        )
        generation_request = _canonical({"request_id": request.request_id})
        generation_response = _canonical({"id": "fixture-response", "choices": []})
        _write_transport(
            unit / "generation-provider-transport",
            request=generation_request,
            response=generation_response,
            request_id=request.request_id,
            functional=False,
        )

        if code is None:
            judge_passes: list[FunctionalJudgePassRecord] = []
            functional = ProgramFunctionalOutcomeRecord.from_content(
                assignment_id=assignment.assignment_id,
                contract_id=contract.contract_id,
                evaluator_policy_sha256=evaluator_policy_sha256,
                status=FunctionalOutcomeStatus.FAIL,
                evidence_sha256=canonical_sha256(
                    {
                        "schema_version": "1.0",
                        "terminal": "no_code",
                        "execution_id": execution.execution_id,
                    }
                ),
            )
            judge_attempts = 0
        else:
            request_bytes = canonical_request_bytes(_request_payload(contract, code.code))
            evidence_line = next(
                index for index, line in enumerate(code.code.splitlines(), start=1) if line.strip()
            )
            response_bytes = _canonical(
                {
                    "status": "pass",
                    "requirements": [
                        {
                            "requirement_id": "req_behavior",
                            "verdict": "met",
                            "code_evidence_lines": [evidence_line],
                            "counterexample": None,
                        }
                    ],
                    "rationale": "The required function is present.",
                }
            )
            parsed_status, parsed_requirements, rationale = _parse_response(
                response_bytes,
                contract=contract,
                code=code.code,
            )
            judge_pass = FunctionalJudgePassRecord.from_content(
                assignment_id=assignment.assignment_id,
                contract_id=contract.contract_id,
                pass_id="A",
                evaluator_policy_sha256=evaluator_policy_sha256,
                request_sha256=hashlib.sha256(request_bytes).hexdigest(),
                response_sha256=hashlib.sha256(response_bytes).hexdigest(),
                status=parsed_status,
                requirements=parsed_requirements,
                rationale=rationale,
            )
            judge_passes = [judge_pass]
            functional = ProgramFunctionalOutcomeRecord.from_content(
                assignment_id=assignment.assignment_id,
                contract_id=contract.contract_id,
                evaluator_policy_sha256=evaluator_policy_sha256,
                status=judge_pass.status,
                evidence_sha256=canonical_sha256(
                    {
                        "schema_version": "1.0",
                        "pass_ids": [judge_pass.judge_pass_id],
                        "decision": judge_pass.status.value,
                        "mode": "single_pass",
                    }
                ),
            )
            _write_transport(
                unit / "functional-judge-transport",
                request=request_bytes,
                response=response_bytes,
                request_id=None,
                functional=True,
            )
            judge_attempts = 1
        _write_jsonl(
            unit / "functional-judge-passes.jsonl",
            [item.model_dump(mode="json") for item in judge_passes],
        )
        _write_jsonl(
            unit / "functional-outcome.jsonl",
            [functional.model_dump(mode="json")],
        )
        if code is not None:
            trace = extract_python_mechanism_trace(code.code)
            analysis = OracleCodeAnalysis(
                request_id=code.request_id,
                code_id=code.code_id,
                code_sha256=code.code_sha256,
                prompt_id=code.prompt_id,
                model_id=code.model_id,
                seed_id=code.seed_id,
                parse_ok=True,
                functional_ok=True,
                security_label=SecurityLabel.UNKNOWN,
                evaluability=OracleEvaluability.UNKNOWN_COVERAGE,
                severity="none",
                findings=(),
                analyzers=tuple(
                    AnalyzerProvenanceRecord(
                        schema_version="1.0",
                        analyzer=analyzer,
                        version="fixture-1",
                        policy_sha256=("8" if analyzer == "semgrep" else "9") * 64,
                    )
                    for analyzer in ("semgrep", "bandit")
                ),
                mechanism_trace=trace,
            )
            _write_json(unit / "oracle-analysis.json", _json_value(analysis))
            _write_json(
                unit / "oracle-binding.json",
                {
                    "schema_version": "1.0",
                    "assignment_id": assignment.assignment_id,
                    "request_id": code.request_id,
                    "code_id": code.code_id,
                    "binding_performed_after_blind_analysis": True,
                },
            )
            _write_json(
                unit / "oracle-decision.json",
                _json_value(_profile_decision_payload(analysis, profiles[cwe])),
            )
            _write_analyzer_transport(unit)
        _write_json(
            unit / "status.json",
            {
                "schema_version": "1.0",
                "assignment_id": assignment.assignment_id,
                "status": "COMPLETE",
                "generated": int(not terminal),
                "terminal_no_code": int(terminal),
                "generation_provider_attempts": 1,
                "functional_judge_provider_attempts": judge_attempts,
                "oracle_results": int(not terminal),
                "oracle_decisions": int(not terminal),
            },
        )
        _manifest(unit)

    _write_json(
        live_dir / "live-config.json",
        {
            "schema_version": "1.0",
            "gate_c_live_id": "dev-canary-test",
            "task_selection_policy": "explicit_dev_canary",
            "expected_assignments": task_count * 2,
            "pilot_assignment_id": min(assignment_ids),
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
            "app_config_sha256": "e" * 64,
        },
    )
    generated_count = task_count * 2 - int(include_terminal_no_code)
    complete_report = {
        "schema_version": "1.0",
        "phase": "remaining",
        "status": "GATE_C_LIVE_COMPLETE",
        "counts": {
            "expected_assignments": task_count * 2,
            "completed": task_count * 2,
            "running": 0,
            "errors": 0,
            "pending": 0,
            "generation_provider_attempts": task_count * 2,
            "functional_judge_provider_attempts": generated_count,
            "oracle_results": generated_count,
        },
        "completed_assignment_ids": sorted(assignment_ids),
        "failed_assignment_ids": [],
    }
    root_report_name = (
        "report-remaining.json"
        if remaining_attempt == 1
        else f"report-remaining-{remaining_attempt:03d}.json"
    )
    _write_json(live_dir / root_report_name, complete_report)
    pilot_snapshot = {
        "schema_version": "1.0",
        "pilot_phase_snapshot_id": "gate_c_live_pilot_snapshot_" + "1" * 64,
    }
    pilot_path = live_dir / "phases" / "phase-001-pilot" / "phase-snapshot.json"
    _write_json(pilot_path, pilot_snapshot)
    final_phase_relative = (
        "phases/phase-002-remaining/report.json"
        if remaining_attempt == 1
        else f"phases/phase-remaining-{remaining_attempt:03d}/report.json"
    )
    phase_path = live_dir / Path(*PurePosixPath(final_phase_relative).parts)
    _write_json(phase_path, complete_report)
    receipt = {
        "schema_version": "1.0",
        "authorization_receipt_id": "gate_c_live_authorization_receipt_" + "2" * 64,
    }
    receipt_path = live_dir / "authorization-receipt-remaining.json"
    _write_json(receipt_path, receipt)
    completed = sorted(assignment_ids)
    remaining_actuals = {
        "generation_provider_attempts": 0,
        "functional_judge_provider_attempts": 0,
        "oracle_executions": 0,
    }
    for assignment_id in completed[1:]:
        status = json.loads(
            (live_dir / "units" / assignment_id / "status.json").read_text(encoding="utf-8")
        )
        remaining_actuals["generation_provider_attempts"] += status["generation_provider_attempts"]
        remaining_actuals["functional_judge_provider_attempts"] += status[
            "functional_judge_provider_attempts"
        ]
        remaining_actuals["oracle_executions"] += status["oracle_results"]
    root_payload = {
        "schema_version": "1.0",
        "provenance_version": "gate_c_live_final_root_v2",
        "status": "GATE_C_LIVE_ROOT_READY",
        "completion_marker": "artifact-manifest.json",
        "scientific_claim_allowed": False,
        "gate_c_live_id": "dev-canary-test",
        "source_plan_manifest_sha256": sha256_file(plan_dir / "artifact-manifest.json"),
        "app_config_sha256": "e" * 64,
        "base_live_config_sha256": sha256_file(live_dir / "live-config.json"),
        "pilot_phase_snapshot_id": pilot_snapshot["pilot_phase_snapshot_id"],
        "pilot_phase_snapshot_sha256": sha256_file(pilot_path),
        "authorization_receipt_id": receipt["authorization_receipt_id"],
        "authorization_receipt_path": "authorization-receipt-remaining.json",
        "authorization_receipt_sha256": sha256_file(receipt_path),
        "final_phase_report_path": final_phase_relative,
        "final_phase_report_sha256": sha256_file(phase_path),
        "root_report_sha256": sha256_file(live_dir / root_report_name),
        "completed_assignment_ids": completed,
        "completed_assignment_ids_sha256": hashlib.sha256(_canonical(completed)).hexdigest(),
        "typed_remaining_actuals": remaining_actuals,
        "typed_cumulative_actuals": {
            "generation_provider_attempts": task_count * 2,
            "functional_judge_provider_attempts": generated_count,
            "oracle_executions": generated_count,
        },
    }
    _write_json(
        live_dir / "root-provenance.json",
        {
            **root_payload,
            "root_provenance_id": "gate_c_live_root_provenance_" + canonical_sha256(root_payload),
        },
    )
    _manifest(live_dir)
    return plan_dir, live_dir


def _jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _unit_dirs(live_dir: Path, *, generated: bool | None = None) -> list[Path]:
    units = sorted((live_dir / "units").iterdir())
    if generated is None:
        return units
    return [
        unit
        for unit in units
        if bool(json.loads((unit / "status.json").read_text(encoding="utf-8"))["generated"])
        is generated
    ]


def _reseal(live_dir: Path, unit_dir: Path) -> None:
    _manifest(unit_dir)
    _manifest(live_dir)


def _rewrite_root_provenance(live_dir: Path, **updates: object) -> None:
    path = live_dir / "root-provenance.json"
    provenance = json.loads(path.read_text(encoding="utf-8"))
    provenance.pop("root_provenance_id")
    provenance.update(updates)
    path.unlink()
    _write_json(
        path,
        {
            **provenance,
            "root_provenance_id": "gate_c_live_root_provenance_" + canonical_sha256(provenance),
        },
    )
    _manifest(live_dir)


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
    assert report["measurement_method"] == "ast_validated_single_shot_llm"
    assert report["functional_variable"] == "Y_F^J"
    assert report["executable_functional_tests_performed"] is False
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
        "functional_unknown": 0,
        "post_randomization_filtered": 0,
        "errors": 0,
        "pending": 0,
    }
    summaries = _jsonl(output_dir / "paired-summaries.jsonl")
    overall = {row["outcome_id"]: row for row in summaries if row["scope"] == "overall"}
    assert overall["y_cwe_secure"]["target_rate"] == 0.5
    assert overall["y_cwe_secure"]["noop_rate"] == 0.0
    assert overall["y_cwe_secure"]["paired_target_minus_noop"] == 0.5
    assert overall["y_functional"]["paired_target_minus_noop"] == -0.5
    assert overall["y_secure_functional"]["paired_target_minus_noop"] == 0.5
    assert all(row["unknown_itt_value"] == 0 for row in summaries)
    coverage = next(
        row for row in _jsonl(output_dir / "coverage.jsonl") if row["scope"] == "overall"
    )
    assert coverage["security_evaluable_assignments"] == 3
    assert coverage["security_evaluable_rate"] == 0.75
    assert coverage["complete_security_pairs"] == 1
    assert coverage["complete_security_pair_rate"] == 0.5
    assert coverage["functional_evaluable_assignments"] == 4
    assert coverage["complete_functional_pairs"] == 2
    provenance = json.loads((output_dir / "provenance.json").read_text(encoding="utf-8"))
    assert provenance["measurement_method"] == "ast_validated_single_shot_llm"
    assert provenance["functional_variable"] == "Y_F^J"
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

    with pytest.raises(ValueError, match="source plan|plan policy"):
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


def test_dev_canary_requires_the_final_live_root(tmp_path: Path) -> None:
    plan_dir, live_dir = _fixture(tmp_path)
    (live_dir / "artifact-manifest.json").unlink()

    with pytest.raises(ValueError, match="final live root"):
        analyze_dev_canary(
            plan_dir=plan_dir,
            live_run_dir=live_dir,
            output_dir=tmp_path / "analysis",
            command_argv=("analyze_dev_canary",),
        )


def test_dev_canary_rejects_deleted_authenticated_leaf(tmp_path: Path) -> None:
    plan_dir, live_dir = _fixture(tmp_path)
    unit = _unit_dirs(live_dir, generated=True)[0]
    (unit / "functional-judge-transport" / "response.json").unlink()
    _reseal(live_dir, unit)

    with pytest.raises((ValueError, OSError)):
        analyze_dev_canary(
            plan_dir=plan_dir,
            live_run_dir=live_dir,
            output_dir=tmp_path / "analysis",
            command_argv=("analyze_dev_canary",),
        )


def test_dev_canary_rejects_contract_substitution(tmp_path: Path) -> None:
    plan_dir, live_dir = _fixture(tmp_path)
    units = _unit_dirs(live_dir, generated=True)
    target = units[0]
    replacement = next(
        unit
        for unit in units[1:]
        if _jsonl(unit / "functional-contract.jsonl")[0]["task_id"]
        != _jsonl(target / "functional-contract.jsonl")[0]["task_id"]
    )
    path = target / "functional-contract.jsonl"
    path.unlink()
    path.write_bytes((replacement / "functional-contract.jsonl").read_bytes())
    _reseal(live_dir, target)

    with pytest.raises(ValueError, match="terminal unit"):
        analyze_dev_canary(
            plan_dir=plan_dir,
            live_run_dir=live_dir,
            output_dir=tmp_path / "analysis",
            command_argv=("analyze_dev_canary",),
        )


def test_dev_canary_rejects_rewritten_oracle_decision(tmp_path: Path) -> None:
    plan_dir, live_dir = _fixture(tmp_path)
    unit = _unit_dirs(live_dir, generated=True)[0]
    path = unit / "oracle-decision.json"
    decision = json.loads(path.read_text(encoding="utf-8"))
    decision["security_label"] = "unknown"
    path.unlink()
    _write_json(path, decision)
    _reseal(live_dir, unit)

    with pytest.raises(ValueError, match="profile decision"):
        analyze_dev_canary(
            plan_dir=plan_dir,
            live_run_dir=live_dir,
            output_dir=tmp_path / "analysis",
            command_argv=("analyze_dev_canary",),
        )


def test_dev_canary_rejects_forged_terminal_pass(tmp_path: Path) -> None:
    plan_dir, live_dir = _fixture(tmp_path)
    unit = _unit_dirs(live_dir, generated=False)[0]
    assignment_id = _jsonl(unit / "assignment.jsonl")[0]["assignment_id"]
    contract_id = _jsonl(unit / "functional-contract.jsonl")[0]["contract_id"]
    path = unit / "functional-outcome.jsonl"
    evaluator_policy_sha256 = _jsonl(path)[0]["evaluator_policy_sha256"]
    path.unlink()
    forged = ProgramFunctionalOutcomeRecord.from_content(
        assignment_id=assignment_id,
        contract_id=contract_id,
        evaluator_policy_sha256=evaluator_policy_sha256,
        status=FunctionalOutcomeStatus.PASS,
        evidence_sha256="f" * 64,
    )
    _write_jsonl(path, [forged.model_dump(mode="json")])
    _reseal(live_dir, unit)

    with pytest.raises(ValueError, match="functional outcome evidence"):
        analyze_dev_canary(
            plan_dir=plan_dir,
            live_run_dir=live_dir,
            output_dir=tmp_path / "analysis",
            command_argv=("analyze_dev_canary",),
        )


def test_twelve_task_dev_canary_branch_is_supported(tmp_path: Path) -> None:
    plan_dir, live_dir = _fixture(
        tmp_path,
        task_count=12,
        include_terminal_no_code=False,
    )
    report = analyze_dev_canary(
        plan_dir=plan_dir,
        live_run_dir=live_dir,
        output_dir=tmp_path / "analysis",
        command_argv=("analyze_dev_canary", "--fixture-12"),
    )

    assert report["counts"]["tasks"] == 12
    assert report["counts"]["assignments"] == 24
    assert report["counts"]["by_cwe"] == {"CWE-78": 6, "CWE-89": 6}
    assert report["measurement_method"] == "ast_validated_single_shot_llm"


def test_dev_canary_rejects_self_consistent_forged_judge_policy(tmp_path: Path) -> None:
    plan_dir, live_dir = _fixture(tmp_path)
    unit = _unit_dirs(live_dir, generated=True)[0]
    pass_path = unit / "functional-judge-passes.jsonl"
    outcome_path = unit / "functional-outcome.jsonl"
    original_pass = _jsonl(pass_path)[0]
    forged_policy = "f" * 64
    forged_pass = FunctionalJudgePassRecord.from_content(
        assignment_id=original_pass["assignment_id"],
        contract_id=original_pass["contract_id"],
        pass_id=original_pass["pass_id"],
        evaluator_policy_sha256=forged_policy,
        request_sha256=original_pass["request_sha256"],
        response_sha256=original_pass["response_sha256"],
        status=original_pass["status"],
        requirements=original_pass["requirements"],
        rationale=original_pass["rationale"],
    )
    forged_outcome = ProgramFunctionalOutcomeRecord.from_content(
        assignment_id=forged_pass.assignment_id,
        contract_id=forged_pass.contract_id,
        evaluator_policy_sha256=forged_policy,
        status=forged_pass.status,
        evidence_sha256=canonical_sha256(
            {
                "schema_version": "1.0",
                "pass_ids": [forged_pass.judge_pass_id],
                "decision": forged_pass.status.value,
                "mode": "single_pass",
            }
        ),
    )
    pass_path.unlink()
    outcome_path.unlink()
    _write_jsonl(pass_path, [forged_pass.model_dump(mode="json")])
    _write_jsonl(outcome_path, [forged_outcome.model_dump(mode="json")])
    _reseal(live_dir, unit)

    with pytest.raises(ValueError, match="functional outcome binding"):
        analyze_dev_canary(
            plan_dir=plan_dir,
            live_run_dir=live_dir,
            output_dir=tmp_path / "analysis",
            command_argv=("analyze_dev_canary",),
        )


def test_dev_canary_rejects_noncanonical_authoritative_path(tmp_path: Path) -> None:
    plan_dir, live_dir = _fixture(tmp_path)
    _rewrite_root_provenance(
        live_dir,
        authorization_receipt_path="../authorization-receipt-remaining.json",
    )

    with pytest.raises(ValueError, match="authoritative root path"):
        analyze_dev_canary(
            plan_dir=plan_dir,
            live_run_dir=live_dir,
            output_dir=tmp_path / "analysis",
            command_argv=("analyze_dev_canary",),
        )


def test_dev_canary_accepts_retry_final_phase(tmp_path: Path) -> None:
    plan_dir, live_dir = _fixture(tmp_path, remaining_attempt=3)
    report = analyze_dev_canary(
        plan_dir=plan_dir,
        live_run_dir=live_dir,
        output_dir=tmp_path / "analysis",
        command_argv=("analyze_dev_canary", "--retry-final"),
    )

    assert report["status"] == "DEV_CANARY_PAIRED_SUMMARY_COMPLETE"


def test_dev_canary_rejects_retry_bound_to_the_wrong_final_phase(tmp_path: Path) -> None:
    plan_dir, live_dir = _fixture(tmp_path, remaining_attempt=3)
    source = live_dir / "phases" / "phase-remaining-003" / "report.json"
    decoy = live_dir / "phases" / "phase-002-remaining" / "report.json"
    decoy.parent.mkdir(parents=True)
    decoy.write_bytes(source.read_bytes())
    _rewrite_root_provenance(
        live_dir,
        final_phase_report_path="phases/phase-002-remaining/report.json",
        final_phase_report_sha256=sha256_file(decoy),
    )

    with pytest.raises(ValueError, match="final live root provenance"):
        analyze_dev_canary(
            plan_dir=plan_dir,
            live_run_dir=live_dir,
            output_dir=tmp_path / "analysis",
            command_argv=("analyze_dev_canary",),
        )

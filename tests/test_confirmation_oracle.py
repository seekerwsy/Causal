from __future__ import annotations

from pathlib import Path
import shutil
import threading
import traceback

import pytest
from pydantic import ValidationError

from secaware.generation.request_planner import plan_confirmation_requests
from secaware.generation.result_importer import canonical_generated_code_from_request
from secaware.io.jsonl import read_jsonl
from secaware.io.run_store import RunStore
from secaware.io.transaction import ArtifactTransaction, TransactionStateError
from secaware.oracle.aggregator import run_oracle_batch
from secaware.oracle.policy import load_policy_bundle
from secaware.oracle.runner import AnalyzerProcessResult
from secaware.pipeline.manifest import read_stage_manifest
import secaware.pipeline.stage_contracts as stage_contracts
from secaware.cli import app as pipeline_app
from typer.testing import CliRunner
from secaware import cli as pipeline_cli
from secaware.pipeline.stages.confirmation_generation import run_confirmation_generation_stage
from secaware.pipeline.stages.confirmation_oracle import (
    run_confirmation_oracle_stage,
    validate_confirmation_oracle_coverage,
)
import secaware.pipeline.stages.confirmation_oracle as confirmation_oracle_module
from secaware.pipeline.stages.prompt_variants import run_prompt_variant_freeze_stage
from secaware.pipeline.stages.randomization import run_confirmation_randomization_stage
from secaware.config import AppConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.experiments import (
    AssignmentExecutionRecord,
    AssignmentExecutionStatus,
    AssignmentRecord,
)
from secaware.schema.generation import provider_provenance_sha256
from secaware.schema.records import CanonicalGeneratedCodeRecord
from secaware.schema.experiments import ArmRole
from secaware.schema.generation import GenerationProvenance
from secaware.schema.oracle import OracleRecord

from test_confirmation_generation_planner import _assignment_and_variant, _generation_config
from test_oracle_engine import FakeRunner
from test_prompt_variant_freeze_stage import _stage_store


_POLICY_LOCK = (
    __import__("pathlib").Path(__file__).parents[1]
    / "policies"
    / "oracle"
    / "python"
    / "policy.lock.json"
)


def _confirmation_code(*, task_id: str = "task-confirmation"):
    assignment, variant = _assignment_and_variant(task_id=task_id)
    request = plan_confirmation_requests(
        (assignment,), (variant,), _generation_config()
    )[0]
    code = canonical_generated_code_from_request(
        request,
        "def answer():\n    return 42\n",
        GenerationProvenance(producer="confirmation-provider"),
        provider_result_sha256="a" * 64,
        provider_usage_sha256="b" * 64,
        provider_runtime_sha256="c" * 64,
        provider_policy_sha256="d" * 64,
        provider_attempt_count=1,
    )
    return assignment, variant, code


def _confirmation_oracle_payload() -> dict[str, object]:
    assignment, _variant, code = _confirmation_code()
    return {
        "schema_version": "1.2",
        "request_id": code.request_id,
        "code_id": code.code_id,
        "code_sha256": code.code_sha256,
        "prompt_id": code.prompt_id,
        "condition": "confirm_arm",
        "model_id": code.model_id,
        "seed_id": code.seed_id,
        "hypothesis_id": code.hypothesis_id,
        "assignment_id": assignment.assignment_id,
        "target_spec_id": assignment.target_spec_id,
        "target_instance_id": assignment.target_instance_id,
        "arm_protocol_id": assignment.arm_protocol_id,
        "protocol_instance_id": assignment.protocol_instance_id,
        "variant_id": assignment.variant_id,
        "arm_role": assignment.arm_role,
        "parse_ok": True,
        "functional_ok": True,
        "security_label": "secure",
        "evaluability": "evaluable",
        "severity": "none",
        "findings": [],
        "analyzers": [
            {
                "schema_version": "1.0",
                "analyzer": analyzer,
                "version": "1",
                "policy_sha256": "e" * 64,
            }
            for analyzer in ("semgrep", "bandit")
        ],
    }


def _execution_for(assignment: AssignmentRecord, code: CanonicalGeneratedCodeRecord):
    return AssignmentExecutionRecord.from_content(
        assignment_id=assignment.assignment_id,
        request_id=code.request_id,
        status=AssignmentExecutionStatus.GENERATED,
        provider_result_sha256=code.provider_result_sha256,
        provider_provenance_sha256=provider_provenance_sha256(
            code.generation_provenance
        ),
        provider_runtime_sha256=code.provider_runtime_sha256,
        provider_policy_sha256=code.provider_policy_sha256,
        usage_sha256=code.provider_usage_sha256,
        attempt_count=code.provider_attempt_count,
        code_id=code.code_id,
        code_sha256=code.code_sha256,
        terminal_reason=None,
    )


def test_confirmation_oracle_preserves_all_assignment_coordinates(monkeypatch) -> None:
    monkeypatch.setattr(
        "secaware.oracle.aggregator.validate_analyzer_runtime", lambda: object()
    )
    assignment, _variant, code = _confirmation_code()

    record = run_oracle_batch(
        [code], load_policy_bundle(_POLICY_LOCK), runner=FakeRunner()
    )[0]

    assert record.schema_version == "1.2"
    assert record.condition == "confirm_arm"
    assert record.hypothesis_id == assignment.experimental_unit.hypothesis_id
    assert record.assignment_id == assignment.assignment_id
    assert record.target_spec_id == assignment.target_spec_id
    assert record.target_instance_id == assignment.target_instance_id
    assert record.arm_protocol_id == assignment.arm_protocol_id
    assert record.protocol_instance_id == assignment.protocol_instance_id
    assert record.variant_id == assignment.variant_id
    assert record.arm_role is assignment.arm_role
    assert record.seed_id == assignment.seed_id
    assert record.model_id == assignment.experimental_unit.model_id
    assert record.request_id == code.request_id
    assert record.code_id == code.code_id
    assert record.code_sha256 == code.code_sha256


def test_oracle_schema_discriminates_observed_and_confirmation_records() -> None:
    confirmed = OracleRecord.model_validate(_confirmation_oracle_payload())
    assert confirmed.condition == "confirm_arm"

    observed = _confirmation_oracle_payload()
    observed.update(condition="observed", hypothesis_id=None)
    for field in (
        "assignment_id",
        "target_spec_id",
        "target_instance_id",
        "arm_protocol_id",
        "protocol_instance_id",
        "variant_id",
        "arm_role",
    ):
        observed[field] = None
    assert OracleRecord.model_validate(observed).condition == "observed"

    for field in (
        "hypothesis_id",
        "assignment_id",
        "target_spec_id",
        "target_instance_id",
        "arm_protocol_id",
        "protocol_instance_id",
        "variant_id",
        "arm_role",
    ):
        invalid = _confirmation_oracle_payload()
        invalid[field] = None
        with pytest.raises(ValidationError):
            OracleRecord.model_validate(invalid)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("assignment_id", "assignment_" + "f" * 64),
        ("target_spec_id", "target_" + "f" * 64),
        ("target_instance_id", "target_instance_" + "f" * 64),
        ("arm_protocol_id", "arm_protocol_" + "f" * 64),
        ("protocol_instance_id", "protocol_instance_" + "f" * 64),
        ("variant_id", "variant_" + "f" * 64),
        ("arm_role", ArmRole.NOOP_REWRITE),
        ("seed_id", 999),
    ],
)
def test_confirmation_oracle_cannot_drift_from_canonical_code(
    field: str, value: object
) -> None:
    payload = _confirmation_oracle_payload()
    payload[field] = value
    # A standalone record can only establish local shape. The stage relation
    # validator must reject every assignment/code coordinate drift.
    record = OracleRecord.model_validate(payload)
    assignment, _variant, code = _confirmation_code()
    execution = _execution_for(assignment, code)
    assert getattr(record, field) == value
    with pytest.raises(SecAwareError):
        from secaware.pipeline.stages.confirmation_oracle import (
            validate_confirmation_oracle_coverage,
        )

        validate_confirmation_oracle_coverage(
            (assignment,), (execution,), (code,), (record,)
        )


def test_confirmation_oracle_stage_surface_exists() -> None:
    from secaware.pipeline.stages.confirmation_oracle import (
        validate_confirmation_oracle_coverage,
    )

    assert callable(validate_confirmation_oracle_coverage)


def test_confirmation_oracle_fingerprint_binds_every_direct_contract() -> None:
    contract = stage_contracts.confirmation_oracle_stage_contract_payload()
    assert {
        "app_config_schema",
        "oracle_config_schema",
        "assignment_schema",
        "execution_schema",
        "request_schema",
        "code_schema",
        "oracle_schema",
        "target_schema",
        "target_instance_schema",
        "protocol_schema",
        "protocol_instance_schema",
        "variant_schema",
        "producer_manifest_schema",
        "runtime_callable_bundle",
        "output_policy",
    } <= set(contract)
    baseline = stage_contracts.confirmation_oracle_stage_contract_sha256(
        "run-oracle-confirmation"
    )
    original = stage_contracts._schema_sha256

    def drift(model: type) -> str:
        if model is OracleRecord:
            return "f" * 64
        return original(model)

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(stage_contracts, "_schema_sha256", drift)
        assert (
            stage_contracts.confirmation_oracle_stage_contract_sha256(
                "run-oracle-confirmation"
            )
            != baseline
        )


def test_run_oracle_confirmation_cli_maps_to_confirm_arm_stage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = AppConfig.model_validate(
        __import__("secaware.config", fromlist=["load_config"]).load_config(
            "configs/demo.yaml"
        ).model_dump(mode="json")
    )
    store = RunStore(config)
    called: list[tuple[AppConfig, RunStore, bool]] = []
    monkeypatch.setattr(pipeline_cli, "_load", lambda _config, _run_dir: (config, store))
    monkeypatch.setattr(
        pipeline_cli,
        "run_confirmation_oracle_stage",
        lambda cfg, run_store, *, force: called.append((cfg, run_store, force)),
        raising=False,
    )

    result = CliRunner().invoke(
        pipeline_app,
        [
            "run-oracle",
            "--config",
            str(tmp_path / "unused.yaml"),
            "--condition",
            "confirmation",
            "--force",
        ],
    )

    assert result.exit_code == 0, result.stdout
    assert called == [(config, store, True)]


@pytest.mark.parametrize(
    "control",
    (MemoryError("memory"), KeyboardInterrupt("keyboard"), SystemExit("exit")),
)
def test_confirmation_oracle_preserves_fatal_identity_before_artifact_access(
    tmp_path: Path, control: BaseException
) -> None:
    config = __import__("secaware.config", fromlist=["load_config"]).load_config(
        "configs/demo.yaml", run_dir=tmp_path / "run"
    )
    store = RunStore(config)

    def fatal() -> object:
        raise control

    with pytest.raises(type(control)) as captured:
        run_confirmation_oracle_stage(
            config,
            store,
            force=False,
            runner=_StageRunner(),
            runtime_validator=fatal,
        )

    assert captured.value is control


def test_confirmation_oracle_aggregator_preserves_memoryerror_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "secaware.oracle.aggregator.validate_analyzer_runtime", lambda: object()
    )
    _assignment, _variant, code = _confirmation_code()
    control = MemoryError("analyzer-memory")

    def fatal_runner(*_args: object, **_kwargs: object) -> AnalyzerProcessResult:
        raise control

    with pytest.raises(MemoryError) as captured:
        run_oracle_batch(
            (code,), load_policy_bundle(_POLICY_LOCK), runner=fatal_runner
        )
    assert captured.value is control


class _StageRunner:
    def __init__(
        self,
        *,
        fail: str | None = None,
        reverse: bool = False,
        control: BaseException | None = None,
        on_analysis=None,
    ) -> None:
        self.fail = fail
        self.reverse = reverse
        self.control = control
        self.on_analysis = on_analysis
        self.analysis = FakeRunner()
        self.version_calls = 0
        self.analysis_calls = 0

    def __call__(
        self,
        argv,
        *,
        cwd: Path,
        timeout_seconds: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
    ) -> AnalyzerProcessResult:
        argv = tuple(argv)
        if argv[-1:] == ("--version",):
            self.version_calls += 1
            analyzer = "bandit" if "bandit" in Path(argv[0]).name.casefold() else "semgrep"
            if self.fail == f"{analyzer}_version":
                raise OSError("private version failure")
            if self.fail == "version_drift" and self.version_calls >= 3:
                return AnalyzerProcessResult(
                    returncode=0,
                    stdout=b"9.9.9\n",
                    argv_sha256="f" * 64,
                )
            stdout = (
                b"bandit 1.9.4\n  python version = 3.11.9 (main) [MSC v.1938]\n"
                if analyzer == "bandit"
                else b"1.168.0\n"
            )
            return AnalyzerProcessResult(
                returncode=0,
                stdout=stdout,
                argv_sha256=("b" if analyzer == "bandit" else "a") * 64,
            )
        self.analysis_calls += 1
        if self.on_analysis is not None:
            self.on_analysis(self.analysis_calls)
        if self.control is not None:
            raise self.control
        if self.fail == "analysis":
            raise OSError("private analyzer failure")
        return self.analysis(
            argv,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
        )


@pytest.fixture(scope="module")
def _generated_confirmation_store(tmp_path_factory: pytest.TempPathFactory):
    config, store = _stage_store(
        tmp_path_factory.mktemp("confirmation-oracle-base"), task_count=20
    )
    run_prompt_variant_freeze_stage(config, store, force=False)
    run_confirmation_randomization_stage(config, store, force=False)
    run_confirmation_generation_stage(config, store, force=False)
    return config, store


def _copied_store(base, tmp_path: Path) -> tuple[AppConfig, RunStore]:
    config, store = base
    destination = tmp_path / "run"
    shutil.copytree(store.root, destination)
    payload = config.model_dump(mode="json")
    payload["run"]["output_dir"] = str(destination)
    copied_config = AppConfig.model_validate(payload)
    return copied_config, RunStore(copied_config)


def _fresh_generated_store(root: Path) -> tuple[AppConfig, RunStore]:
    config, store = _stage_store(root, task_count=20)
    run_prompt_variant_freeze_stage(config, store, force=False)
    run_confirmation_randomization_stage(config, store, force=False)
    run_confirmation_generation_stage(config, store, force=False)
    return config, store


def _stage_run(config: AppConfig, store: RunStore, runner: _StageRunner, *, force=False):
    return run_confirmation_oracle_stage(
        config,
        store,
        force=force,
        runner=runner,
        runtime_validator=lambda: object(),
    )


def test_confirmation_oracle_stage_publishes_exact_generated_subset(
    _generated_confirmation_store, tmp_path: Path
) -> None:
    config, store = _generated_confirmation_store
    runner = _StageRunner()

    result = _stage_run(config, store, runner)

    assignments = read_jsonl(
        store.path("interventions", "assignments.jsonl"),
        __import__("secaware.schema.experiments", fromlist=["AssignmentRecord"]).AssignmentRecord,
        required=True,
        allow_empty=False,
    )
    executions = read_jsonl(
        store.path("generation", "confirmation_execution.jsonl"),
        AssignmentExecutionRecord,
        required=True,
        allow_empty=False,
    )
    codes = read_jsonl(
        store.path("generation", "confirmation_code.jsonl"),
        __import__("secaware.schema.records", fromlist=["CanonicalGeneratedCodeRecord"]).CanonicalGeneratedCodeRecord,
        required=True,
        allow_empty=True,
    )
    oracles = read_jsonl(
        store.path("oracle", "confirmation_oracle.jsonl"),
        OracleRecord,
        required=True,
        allow_empty=True,
    )
    assert result.assignment_count == len(assignments)
    assert result.oracle_count == result.generated_count == len(codes) == len(oracles)
    assert result.terminal_no_code_count == len(assignments) - len(codes)
    assert validate_confirmation_oracle_coverage(assignments, executions, codes, oracles) == result
    manifest = read_stage_manifest(store.path(".stages", "run-oracle-confirmation.json"))
    assert manifest.outputs == ["oracle/confirmation_oracle.jsonl"]
    assert manifest.policy_sha256 is not None
    assert runner.analysis_calls == 2


@pytest.mark.parametrize("mutation", ("missing", "extra", "duplicate"))
def test_confirmation_oracle_coverage_rejects_missing_extra_or_duplicate(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    monkeypatch.setattr(
        "secaware.oracle.aggregator.validate_analyzer_runtime", lambda: object()
    )
    assignment, _variant, code = _confirmation_code()
    execution = _execution_for(assignment, code)
    oracle = run_oracle_batch(
        (code,), load_policy_bundle(_POLICY_LOCK), runner=FakeRunner()
    )[0]
    oracles = () if mutation == "missing" else (oracle, oracle)
    if mutation == "extra":
        other_payload = oracle.model_dump(mode="python")
        other_payload["request_id"] = "req_" + "f" * 64
        oracles = (oracle, OracleRecord.model_validate(other_payload))
    with pytest.raises(SecAwareError):
        validate_confirmation_oracle_coverage(
            (assignment,), (execution,), (code,), oracles
        )


def test_terminal_no_code_assignment_has_no_oracle() -> None:
    assignment, _variant, code = _confirmation_code()
    execution = AssignmentExecutionRecord.from_content(
        assignment_id=assignment.assignment_id,
        request_id=code.request_id,
        status=AssignmentExecutionStatus.TERMINAL_NO_CODE,
        provider_result_sha256="a" * 64,
        provider_provenance_sha256="b" * 64,
        provider_runtime_sha256="c" * 64,
        provider_policy_sha256="d" * 64,
        usage_sha256="e" * 64,
        attempt_count=1,
        code_id=None,
        code_sha256=None,
        terminal_reason="content_filter",
    )
    result = validate_confirmation_oracle_coverage((assignment,), (execution,), (), ())
    assert result.generated_count == result.oracle_count == 0
    assert result.terminal_no_code_count == 1


@pytest.mark.parametrize("mutation", ("duplicate_execution", "resealed_hash_drift"))
def test_confirmation_generated_subset_drift_is_rejected_pre_analyzer(
    mutation: str,
) -> None:
    assignment, _variant, code = _confirmation_code()
    execution = _execution_for(assignment, code)
    executions = (execution, execution)
    if mutation == "resealed_hash_drift":
        executions = (
            AssignmentExecutionRecord.from_content(
                assignment_id=assignment.assignment_id,
                request_id=code.request_id,
                status=AssignmentExecutionStatus.GENERATED,
                provider_result_sha256=code.provider_result_sha256,
                provider_provenance_sha256=provider_provenance_sha256(
                    code.generation_provenance
                ),
                provider_runtime_sha256=code.provider_runtime_sha256,
                provider_policy_sha256=code.provider_policy_sha256,
                usage_sha256=code.provider_usage_sha256,
                attempt_count=code.provider_attempt_count,
                code_id=code.code_id,
                code_sha256="f" * 64,
                terminal_reason=None,
            ),
        )
    with pytest.raises(SecAwareError):
        confirmation_oracle_module._validate_generated_code_coverage(
            (assignment,), executions, (code,)
        )


def test_confirmation_oracle_stage_fails_closed_on_missing_tool_or_analyzer(
    _generated_confirmation_store, tmp_path: Path
) -> None:
    for index, failure in enumerate(("semgrep_version", "analysis")):
        config, store = _fresh_generated_store(tmp_path / str(index))
        with pytest.raises(SecAwareError) as captured:
            _stage_run(config, store, _StageRunner(fail=failure))
        assert captured.value.code in {ErrorCode.ANALYZER_FAILED, ErrorCode.ANALYZER_MISSING}
        assert not store.path("oracle", "confirmation_oracle.jsonl").exists()


def _committed_oracle_bytes(config: AppConfig, store: RunStore) -> tuple[bytes, bytes]:
    _stage_run(config, store, _StageRunner(), force=False)
    return _oracle_bytes(store)


def _oracle_bytes(store: RunStore) -> tuple[bytes, bytes]:
    return (
        store.path("oracle", "confirmation_oracle.jsonl").read_bytes(),
        store.path(".stages", "run-oracle-confirmation.json").read_bytes(),
    )


def test_confirmation_oracle_skip_and_tamper_repair(
    _generated_confirmation_store,
) -> None:
    config, store = _generated_confirmation_store
    committed = _committed_oracle_bytes(config, store)
    skipped = _StageRunner()
    _stage_run(config, store, skipped, force=False)
    assert skipped.analysis_calls == 0
    assert _oracle_bytes(store) == committed

    output = store.path("oracle", "confirmation_oracle.jsonl")
    output.write_bytes(committed[0] + b"\n")
    repaired = _StageRunner()
    _stage_run(config, store, repaired, force=False)
    assert repaired.analysis_calls == 2
    assert _oracle_bytes(store) == committed


def test_confirmation_oracle_partial_install_failure_rolls_back(
    _generated_confirmation_store, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, store = _generated_confirmation_store
    committed = _committed_oracle_bytes(config, store)
    real_install = ArtifactTransaction.install

    def fail_after_install(transaction, index: int, candidate: Path) -> None:
        real_install(transaction, index, candidate)
        if index == 0:
            raise TransactionStateError

    monkeypatch.setattr(ArtifactTransaction, "install", fail_after_install)
    with pytest.raises(SecAwareError) as captured:
        _stage_run(config, store, _StageRunner(), force=True)
    assert captured.value.code is ErrorCode.CONTRACT
    assert _oracle_bytes(store) == committed


def test_confirmation_oracle_analyzer_failure_is_public_and_rolls_back(
    _generated_confirmation_store,
) -> None:
    config, store = _generated_confirmation_store
    committed = _committed_oracle_bytes(config, store)
    code = read_jsonl(
        store.path("generation", "confirmation_code.jsonl"),
        CanonicalGeneratedCodeRecord,
        required=True,
        allow_empty=False,
    )[0]
    prompt = code.generation_request.prompt

    with pytest.raises(SecAwareError) as captured:
        _stage_run(config, store, _StageRunner(fail="analysis"), force=True)

    surfaces = "\n".join(
        (
            str(captured.value),
            "".join(traceback.format_exception(captured.value)),
            repr(captured.value.to_dict()),
        )
    )
    assert code.code not in surfaces
    assert prompt not in surfaces
    assert "private analyzer failure" not in surfaces
    assert _oracle_bytes(store) == committed


@pytest.mark.parametrize(
    "control",
    (MemoryError("memory"), KeyboardInterrupt("keyboard"), SystemExit("exit")),
)
def test_confirmation_oracle_preserves_analyzer_fatal_identity_and_rolls_back(
    _generated_confirmation_store, control: BaseException
) -> None:
    config, store = _generated_confirmation_store
    committed = _committed_oracle_bytes(config, store)
    with pytest.raises(type(control)) as captured:
        _stage_run(config, store, _StageRunner(control=control), force=True)
    assert captured.value is control
    assert _oracle_bytes(store) == committed


def test_confirmation_oracle_detects_generation_toctou_and_rolls_back(
    _generated_confirmation_store,
) -> None:
    config, store = _generated_confirmation_store
    committed = _committed_oracle_bytes(config, store)
    code_path = store.path("generation", "confirmation_code.jsonl")
    original = code_path.read_bytes()

    def mutate_once(call: int) -> None:
        if call == 1:
            code_path.write_bytes(original + b"\n")
            code_path.write_bytes(original)

    with pytest.raises(SecAwareError) as captured:
        _stage_run(config, store, _StageRunner(on_analysis=mutate_once), force=True)
    assert captured.value.code is ErrorCode.CONTRACT
    assert code_path.read_bytes() == original
    assert _oracle_bytes(store) == committed


def test_confirmation_oracle_fails_before_analysis_on_resource_or_future_artifact(
    _generated_confirmation_store, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, store = _generated_confirmation_store
    committed = _committed_oracle_bytes(config, store)
    runner = _StageRunner()
    monkeypatch.setattr(confirmation_oracle_module, "_MAX_TOTAL_CODE_BYTES", 1)
    with pytest.raises(SecAwareError):
        _stage_run(config, store, runner, force=True)
    assert runner.analysis_calls == 0
    assert _oracle_bytes(store) == committed

    monkeypatch.undo()
    future = store.path("analysis", "effects.jsonl")
    future.write_text("{}\n", encoding="utf-8")
    runner = _StageRunner()
    try:
        with pytest.raises(SecAwareError):
            _stage_run(config, store, runner, force=True)
        assert runner.analysis_calls == 0
        assert _oracle_bytes(store) == committed
    finally:
        future.unlink(missing_ok=True)


def test_confirmation_oracle_tool_drift_fails_before_analysis_and_preserves_commit(
    _generated_confirmation_store,
) -> None:
    config, store = _generated_confirmation_store
    committed = _committed_oracle_bytes(config, store)
    runner = _StageRunner(fail="version_drift")
    with pytest.raises(SecAwareError) as captured:
        _stage_run(config, store, runner, force=True)
    assert captured.value.code is ErrorCode.POLICY_MISMATCH
    assert runner.analysis_calls == 0
    assert _oracle_bytes(store) == committed


def test_confirmation_oracle_contract_drift_invalidates_skip(
    _generated_confirmation_store, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, store = _generated_confirmation_store
    _committed_oracle_bytes(config, store)
    original = stage_contracts._schema_sha256

    def drift(model: type) -> str:
        if model is OracleRecord:
            return "f" * 64
        return original(model)

    monkeypatch.setattr(stage_contracts, "_schema_sha256", drift)
    runner = _StageRunner()
    _stage_run(config, store, runner, force=False)
    assert runner.analysis_calls == 2


def test_confirmation_oracle_aggregation_is_order_invariant(monkeypatch) -> None:
    monkeypatch.setattr(
        "secaware.oracle.aggregator.validate_analyzer_runtime", lambda: object()
    )
    first = _confirmation_code(task_id="task-confirmation-a")[2]
    second = _confirmation_code(task_id="task-confirmation-b")[2]
    policy = load_policy_bundle(_POLICY_LOCK)
    forward = run_oracle_batch((first, second), policy, runner=FakeRunner())
    reverse = run_oracle_batch((second, first), policy, runner=FakeRunner())
    assert forward == reverse
    assert [item.request_id for item in forward] == sorted(
        (first.request_id, second.request_id)
    )


def test_confirmation_oracle_holds_all_producer_leases(
    _generated_confirmation_store,
) -> None:
    config, owner = _generated_confirmation_store
    _committed_oracle_bytes(config, owner)
    contender = RunStore(config)
    entered = threading.Event()
    release = threading.Event()
    errors: list[BaseException] = []

    def block(call: int) -> None:
        if call == 1:
            entered.set()
            assert release.wait(timeout=15)

    def consume() -> None:
        try:
            _stage_run(config, owner, _StageRunner(on_analysis=block), force=True)
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=consume)
    thread.start()
    assert entered.wait(timeout=15)
    try:
        producers = (
            lambda: run_prompt_variant_freeze_stage(config, contender, force=True),
            lambda: run_confirmation_randomization_stage(config, contender, force=True),
            lambda: run_confirmation_generation_stage(config, contender, force=True),
        )
        for rerun in producers:
            with pytest.raises(SecAwareError) as captured:
                rerun()
            assert captured.value.code is ErrorCode.MANIFEST_CONFLICT
    finally:
        release.set()
        thread.join(timeout=30)
    assert not thread.is_alive()
    assert errors == []

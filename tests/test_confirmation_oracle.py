from __future__ import annotations

from pathlib import Path
import json
import shutil
import threading
import traceback
import inspect

import pytest
from pydantic import ValidationError

from secaware.generation.request_planner import plan_confirmation_requests
from secaware.generation.result_importer import canonical_generated_code_from_request
from secaware.io.jsonl import read_jsonl
from secaware.io.run_store import RunStore
from secaware.io.transaction import ArtifactTransaction, TransactionStateError
from secaware.oracle import aggregator as oracle_aggregator
from secaware.oracle.aggregator import OracleCodeInput, run_oracle_batch, run_oracle_code_batch
from secaware.oracle.policy import load_policy_bundle
from secaware.oracle.runner import AnalyzerProcessResult
from secaware.intervention.graph_patch import IntendedGraphPatchRecord, allowed_delta_sha256
from secaware.pipeline.artifact import canonical_sha256, sha256_path
from secaware.pipeline.manifest import read_stage_manifest, write_stage_manifest
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
from secaware.pipeline.stages.prompt_variants import (
    PROMPT_VARIANT_OUTPUTS,
    run_prompt_variant_freeze_stage,
)
from secaware.pipeline.stages.randomization import run_confirmation_randomization_stage
from secaware.config import AppConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.schema.experiments import (
    AssignmentExecutionRecord,
    AssignmentExecutionStatus,
    AssignmentRecord,
    PreRandomizationExclusionRecord,
    PreRandomizationFailureCode,
    RandomizationManifestRecord,
)
from secaware.schema.generation import provider_provenance_sha256
from secaware.schema.records import CanonicalGeneratedCodeRecord
from secaware.schema.experiments import ArmRole
from secaware.schema.generation import GenerationProvenance
from secaware.schema.oracle import AnalyzerFindingRecord, OracleRecord, SecurityLabel

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
_ACTIVE_STAGE_RUNNER = None


def _valid_runtime():
    return object()


_ACTIVE_RUNTIME_VALIDATOR = _valid_runtime


def _controlled_analyzer_runtime_factory(_config):
    return confirmation_oracle_module._AnalyzerRuntime(
        runner=_ACTIVE_STAGE_RUNNER,
        validator=_ACTIVE_RUNTIME_VALIDATOR,
    )


def _confirmation_code(*, task_id: str = "task-confirmation"):
    assignment, variant = _assignment_and_variant(task_id=task_id)
    request = plan_confirmation_requests((assignment,), (variant,), _generation_config())[0]
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
        provider_provenance_sha256=provider_provenance_sha256(code.generation_provenance),
        provider_runtime_sha256=code.provider_runtime_sha256,
        provider_policy_sha256=code.provider_policy_sha256,
        usage_sha256=code.provider_usage_sha256,
        attempt_count=code.provider_attempt_count,
        code_id=code.code_id,
        code_sha256=code.code_sha256,
        terminal_reason=None,
    )


def test_confirmation_oracle_preserves_all_assignment_coordinates(monkeypatch) -> None:
    monkeypatch.setattr("secaware.oracle.aggregator.validate_analyzer_runtime", lambda: object())
    assignment, _variant, code = _confirmation_code()

    record = run_oracle_batch([code], load_policy_bundle(_POLICY_LOCK), runner=FakeRunner())[0]

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
def test_confirmation_oracle_cannot_drift_from_canonical_code(field: str, value: object) -> None:
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

        validate_confirmation_oracle_coverage((assignment,), (execution,), (code,), (record,))


def test_confirmation_oracle_stage_surface_exists() -> None:
    from secaware.pipeline.stages.confirmation_oracle import (
        validate_confirmation_oracle_coverage,
    )

    assert callable(validate_confirmation_oracle_coverage)


def test_task7_uses_stable_task5_and_task6_public_bundle_validators() -> None:
    import secaware.pipeline.stages.randomization as randomization_stage
    import secaware.pipeline.stages.confirmation_generation as generation_stage

    assert callable(randomization_stage.validate_randomization_artifact_bundle)
    assert callable(generation_stage.validate_confirmation_generation_bundle)


def test_confirmation_oracle_public_surface_has_no_arbitrary_runner_injection() -> None:
    parameters = inspect.signature(run_confirmation_oracle_stage).parameters
    assert "runner" not in parameters
    assert "runtime_validator" not in parameters


def test_oracle_code_input_is_blind_to_experimental_coordinates() -> None:
    from secaware.oracle.aggregator import OracleCodeInput

    assert set(inspect.signature(OracleCodeInput).parameters) == {
        "request_id",
        "code_id",
        "code_sha256",
        "prompt_id",
        "model_id",
        "seed_id",
        "language",
        "code",
    }


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
    baseline = stage_contracts.confirmation_oracle_stage_contract_sha256("run-oracle-confirmation")
    original = stage_contracts._schema_sha256

    def drift(model: type) -> str:
        if model is OracleRecord:
            return "f" * 64
        return original(model)

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(stage_contracts, "_schema_sha256", drift)
        assert (
            stage_contracts.confirmation_oracle_stage_contract_sha256("run-oracle-confirmation")
            != baseline
        )


def test_run_oracle_confirmation_cli_maps_to_confirm_arm_stage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = AppConfig.model_validate(
        __import__("secaware.config", fromlist=["load_config"])
        .load_config("configs/demo.yaml")
        .model_dump(mode="json")
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

    global _ACTIVE_STAGE_RUNNER, _ACTIVE_RUNTIME_VALIDATOR
    _ACTIVE_STAGE_RUNNER = _StageRunner()
    _ACTIVE_RUNTIME_VALIDATOR = fatal
    with pytest.raises(type(control)) as captured:
        run_confirmation_oracle_stage(config, store, force=False)

    assert captured.value is control


def test_confirmation_oracle_aggregator_preserves_memoryerror_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("secaware.oracle.aggregator.validate_analyzer_runtime", lambda: object())
    _assignment, _variant, code = _confirmation_code()
    control = MemoryError("analyzer-memory")

    def fatal_runner(*_args: object, **_kwargs: object) -> AnalyzerProcessResult:
        raise control

    with pytest.raises(MemoryError) as captured:
        run_oracle_batch((code,), load_policy_bundle(_POLICY_LOCK), runner=fatal_runner)
    assert captured.value is control


def _secaware_frame_locals(error: BaseException) -> str:
    retained: list[str] = []
    current = error.__traceback__
    while current is not None:
        if current.tb_frame.f_globals.get("__name__", "").startswith("secaware"):
            retained.append(repr(dict(current.tb_frame.f_locals)))
        current = current.tb_next
    return "\n".join(retained)


def _blind_code_input() -> tuple[AssignmentRecord, CanonicalGeneratedCodeRecord, OracleCodeInput]:
    assignment, _variant, code = _confirmation_code(task_id="task-blind-oracle")
    return assignment, code, OracleCodeInput.from_canonical(code)


def _run_blind_batch(code_input: OracleCodeInput, runner):
    return run_oracle_code_batch(
        (code_input,),
        load_policy_bundle(_POLICY_LOCK),
        semgrep_executable="semgrep",
        bandit_executable="bandit",
        timeout_seconds=120.0,
        max_stdout_bytes=64 * 1024 * 1024,
        max_stderr_bytes=4 * 1024 * 1024,
        runner=runner,
        runtime_validator=_valid_runtime,
    )


def test_oracle_runner_observes_only_code_language_and_policy_coordinates() -> None:
    assignment, code, code_input = _blind_code_input()
    observed: list[tuple[tuple[str, ...], Path]] = []
    fake = FakeRunner()

    def spy(argv, **kwargs):
        observed.append((tuple(argv), kwargs["cwd"]))
        return fake(argv, **kwargs)

    analyses = _run_blind_batch(code_input, spy)
    rendered = repr(observed)
    assert len(analyses) == 1
    assert assignment.assignment_id not in rendered
    assert assignment.variant_id not in rendered
    assert assignment.arm_role.value not in rendered
    assert code.generation_request.prompt not in rendered


def test_blind_oracle_ordinary_failure_releases_sensitive_frame_locals() -> None:
    assignment, code, code_input = _blind_code_input()

    def fail(*_args, **_kwargs):
        raise OSError("private failure")

    with pytest.raises(SecAwareError) as captured:
        _run_blind_batch(code_input, fail)
    retained = _secaware_frame_locals(captured.value)
    assert code.code not in retained
    assert code.generation_request.prompt not in retained
    assert assignment.assignment_id not in retained


@pytest.mark.parametrize(
    "control",
    (MemoryError("memory"), KeyboardInterrupt("keyboard"), SystemExit("exit")),
)
def test_blind_oracle_fatal_failure_releases_sensitive_frame_locals(
    control: BaseException,
) -> None:
    assignment, code, code_input = _blind_code_input()

    def fail(*_args, **_kwargs):
        raise control

    with pytest.raises(type(control)) as captured:
        _run_blind_batch(code_input, fail)
    assert captured.value is control
    retained = _secaware_frame_locals(captured.value)
    assert code.code not in retained
    assert code.generation_request.prompt not in retained
    assert assignment.assignment_id not in retained


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


@pytest.fixture(scope="module", autouse=True)
def _install_controlled_analyzer_runtime_factory():
    original = confirmation_oracle_module._ANALYZER_RUNTIME_FACTORY
    confirmation_oracle_module._ANALYZER_RUNTIME_FACTORY = _controlled_analyzer_runtime_factory
    try:
        yield
    finally:
        confirmation_oracle_module._ANALYZER_RUNTIME_FACTORY = original


@pytest.fixture(scope="module")
def _generated_confirmation_store(tmp_path_factory: pytest.TempPathFactory):
    config, store = _stage_store(tmp_path_factory.mktemp("confirmation-oracle-base"), task_count=20)
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


def _rewrite_producer_outputs(
    store: RunStore,
    stage: str,
    replacements: dict[str, tuple[object, ...]],
) -> None:
    manifest_path = store.path(".stages", f"{stage}.json")
    manifest = read_stage_manifest(manifest_path)
    output_sha256 = dict(manifest.output_sha256)
    for relative, records in replacements.items():
        path = store.root / relative
        payload = "".join(
            json.dumps(
                record.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
            for record in records
        )
        path.write_text(payload, encoding="utf-8", newline="\n")
        output_sha256[relative] = sha256_path(path)
    write_stage_manifest(
        manifest_path,
        type(manifest).model_validate(
            {**manifest.model_dump(mode="json"), "output_sha256": output_sha256}
        ),
    )


def _rewrite_raw_producer_output(store: RunStore, stage: str, relative: str, payload: str) -> None:
    manifest_path = store.path(".stages", f"{stage}.json")
    manifest = read_stage_manifest(manifest_path)
    path = store.root / relative
    path.write_text(payload, encoding="utf-8", newline="\n")
    output_sha256 = dict(manifest.output_sha256)
    output_sha256[relative] = sha256_path(path)
    write_stage_manifest(
        manifest_path,
        type(manifest).model_validate(
            {**manifest.model_dump(mode="json"), "output_sha256": output_sha256}
        ),
    )


def _task4_bundle(store: RunStore) -> dict[str, tuple[object, ...]]:
    return {
        name: tuple(
            read_jsonl(
                store.path("interventions", name),
                model,
                required=True,
                allow_empty=True,
            )
        )
        for name, model in PROMPT_VARIANT_OUTPUTS
    }


def _mutated_task4_group(
    output_name: str, bundle: dict[str, tuple[object, ...]]
) -> tuple[object, ...]:
    records = bundle[output_name]
    if output_name in {
        "target_specs.jsonl",
        "confirmation_protocols.jsonl",
        "prompt_variants.jsonl",
    }:
        return (*records, records[0])
    if output_name in {
        "target_instances.jsonl",
        "confirmation_protocol_instances.jsonl",
        "variant_extraction_proposals.jsonl",
        "variant_prompt_tsg.jsonl",
        "length_matches.jsonl",
    }:
        return records[1:]
    if output_name == "graph_deltas.jsonl":
        original = records[0]
        content = original.model_dump(mode="python", exclude={"schema_version", "delta_id"})
        content["target_changed"] = not bool(original.target_changed)
        replacement = type(original).from_content(**content)
        return (replacement, *records[1:])
    if output_name == "intended_patches.jsonl":
        delta = bundle["graph_deltas.jsonl"][0]
        protocol = bundle["confirmation_protocols.jsonl"][0]
        arm = next(item for item in protocol.arms if item.role is delta.arm_role)
        return (
            IntendedGraphPatchRecord.from_content(
                target_spec_id=delta.target_spec_id,
                target_instance_id=delta.target_instance_id,
                arm_protocol_id=delta.arm_protocol_id,
                protocol_instance_id=delta.protocol_instance_id,
                arm_role=delta.arm_role,
                before_graph_sha256=delta.before_graph_sha256,
                allowed_delta_sha256=allowed_delta_sha256(arm.allowed_delta),
                intended_transitions=arm.allowed_delta.allowed_transitions,
            ),
        )
    if output_name == "pre_randomization_exclusions.jsonl":
        variant = bundle["prompt_variants.jsonl"][0]
        detail_sha256 = canonical_sha256(
            {
                "schema_version": "1.0",
                "protocol_instance_id": variant.protocol_instance_id,
                "failed_arm_roles": [variant.arm_role.value],
                "failure_codes": [PreRandomizationFailureCode.EXECUTION_FAILED.value],
            }
        )
        return (
            PreRandomizationExclusionRecord.from_content(
                hypothesis_id=variant.hypothesis_id,
                target_spec_id=variant.target_spec_id,
                target_instance_id=variant.target_instance_id,
                arm_protocol_id=variant.arm_protocol_id,
                protocol_instance_id=variant.protocol_instance_id,
                task_id=variant.task_id,
                failed_arm_roles=(variant.arm_role,),
                failure_codes=(PreRandomizationFailureCode.EXECUTION_FAILED,),
                detail_sha256=detail_sha256,
            ),
        )
    raise AssertionError(output_name)


def _stage_run(config: AppConfig, store: RunStore, runner: _StageRunner, *, force=False):
    global _ACTIVE_STAGE_RUNNER, _ACTIVE_RUNTIME_VALIDATOR
    _ACTIVE_STAGE_RUNNER = runner
    _ACTIVE_RUNTIME_VALIDATOR = _valid_runtime
    return run_confirmation_oracle_stage(config, store, force=force)


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
        __import__(
            "secaware.schema.records", fromlist=["CanonicalGeneratedCodeRecord"]
        ).CanonicalGeneratedCodeRecord,
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
    monkeypatch.setattr("secaware.oracle.aggregator.validate_analyzer_runtime", lambda: object())
    assignment, _variant, code = _confirmation_code()
    execution = _execution_for(assignment, code)
    oracle = run_oracle_batch((code,), load_policy_bundle(_POLICY_LOCK), runner=FakeRunner())[0]
    oracles = () if mutation == "missing" else (oracle, oracle)
    if mutation == "extra":
        other_payload = oracle.model_dump(mode="python")
        other_payload["request_id"] = "req_" + "f" * 64
        oracles = (oracle, OracleRecord.model_validate(other_payload))
    with pytest.raises(SecAwareError):
        validate_confirmation_oracle_coverage((assignment,), (execution,), (code,), oracles)


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
                provider_provenance_sha256=provider_provenance_sha256(code.generation_provenance),
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
        validate_confirmation_oracle_coverage((assignment,), executions, (code,), ())


@pytest.mark.parametrize(
    "drift",
    (
        "assignment_ids",
        "assignments_sha256",
        "randomization_plan_sha256",
        "rng_version",
        "global_seed",
        "randomization_config",
    ),
)
def test_confirmation_oracle_rejects_randomization_manifest_drift_pre_analyzer(
    _generated_confirmation_store, tmp_path: Path, drift: str
) -> None:
    config, store = _copied_store(_generated_confirmation_store, tmp_path)
    manifests = read_jsonl(
        store.path("interventions", "randomization_manifest.jsonl"),
        RandomizationManifestRecord,
        required=True,
        allow_empty=False,
    )
    manifest = manifests[0]
    if drift == "randomization_config":
        payload = config.model_dump(mode="json")
        payload["randomization"]["min_independent_tasks_per_semantic_protocol"] += 1
        config = AppConfig.model_validate(payload)
        store = RunStore(config)
    elif drift == "rng_version":
        payload = manifest.model_dump(mode="json")
        payload["rng_version"] = "future-rng"
        _rewrite_raw_producer_output(
            store,
            "randomize-confirmation",
            "interventions/randomization_manifest.jsonl",
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        )
    else:
        content = manifest.model_dump(mode="python", exclude={"schema_version", "manifest_id"})
        if drift == "assignment_ids":
            content["assignment_ids"] = tuple(reversed(content["assignment_ids"]))
        elif drift == "assignments_sha256":
            content["assignments_sha256"] = "f" * 64
        elif drift == "randomization_plan_sha256":
            content["randomization_plan_sha256"] = "f" * 64
        else:
            content["global_seed"] += 1
        replacement = RandomizationManifestRecord.from_content(**content)
        _rewrite_producer_outputs(
            store,
            "randomize-confirmation",
            {"interventions/randomization_manifest.jsonl": (replacement,)},
        )
    runner = _StageRunner()
    with pytest.raises(SecAwareError):
        _stage_run(config, store, runner, force=True)
    assert runner.analysis_calls == 0


def test_confirmation_oracle_rejects_full_task4_provenance_mutation_pre_analyzer(
    _generated_confirmation_store, tmp_path: Path
) -> None:
    config, store = _copied_store(_generated_confirmation_store, tmp_path)
    targets = read_jsonl(
        store.path("interventions", "target_specs.jsonl"),
        __import__("secaware.schema.experiments", fromlist=["TargetSpecRecord"]).TargetSpecRecord,
        required=True,
        allow_empty=False,
    )
    _rewrite_producer_outputs(
        store,
        "build-confirmation-variants",
        {"interventions/target_specs.jsonl": (*targets, targets[0])},
    )
    runner = _StageRunner()
    with pytest.raises(SecAwareError):
        _stage_run(config, store, runner, force=True)
    assert runner.analysis_calls == 0


@pytest.mark.parametrize("output_name", tuple(name for name, _model in PROMPT_VARIANT_OUTPUTS))
def test_confirmation_oracle_consumes_every_task4_output_relation_pre_analyzer(
    _generated_confirmation_store, tmp_path: Path, output_name: str
) -> None:
    del tmp_path
    config, store = _generated_confirmation_store
    committed = _committed_oracle_bytes(config, store)
    bundle = _task4_bundle(store)
    artifact = store.path("interventions", output_name)
    producer_manifest = store.path(".stages", "build-confirmation-variants.json")
    previous = (artifact.read_bytes(), producer_manifest.read_bytes())
    try:
        _rewrite_producer_outputs(
            store,
            "build-confirmation-variants",
            {f"interventions/{output_name}": _mutated_task4_group(output_name, bundle)},
        )
        runner = _StageRunner()
        with pytest.raises(SecAwareError):
            _stage_run(config, store, runner, force=True)
        assert runner.analysis_calls == 0
        assert _oracle_bytes(store) == committed
    finally:
        artifact.write_bytes(previous[0])
        producer_manifest.write_bytes(previous[1])


def test_confirmation_oracle_rejects_resigned_duplicate_graph_delta_pre_analyzer(
    _generated_confirmation_store, tmp_path: Path
) -> None:
    del tmp_path
    config, store = _generated_confirmation_store
    committed = _committed_oracle_bytes(config, store)
    bundle = _task4_bundle(store)
    deltas = bundle["graph_deltas.jsonl"]
    artifact = store.path("interventions", "graph_deltas.jsonl")
    producer_manifest = store.path(".stages", "build-confirmation-variants.json")
    previous = (artifact.read_bytes(), producer_manifest.read_bytes())
    try:
        _rewrite_producer_outputs(
            store,
            "build-confirmation-variants",
            {"interventions/graph_deltas.jsonl": (*deltas, deltas[0])},
        )
        runner = _StageRunner()
        with pytest.raises(SecAwareError):
            _stage_run(config, store, runner, force=True)
        assert runner.analysis_calls == 0
        assert _oracle_bytes(store) == committed
    finally:
        artifact.write_bytes(previous[0])
        producer_manifest.write_bytes(previous[1])


@pytest.mark.parametrize(
    "producer_stage",
    ("build-confirmation-variants", "randomize-confirmation", "generate-confirmation"),
)
def test_confirmation_oracle_rejects_producer_manifest_input_hash_drift_pre_analyzer(
    _generated_confirmation_store, tmp_path: Path, producer_stage: str
) -> None:
    del tmp_path
    config, store = _generated_confirmation_store
    committed = _committed_oracle_bytes(config, store)
    manifest_path = store.path(".stages", f"{producer_stage}.json")
    previous = manifest_path.read_bytes()
    manifest = read_stage_manifest(manifest_path)
    inputs = dict(manifest.inputs)
    first = next(iter(inputs))
    inputs[first] = "f" * 64 if inputs[first] != "f" * 64 else "e" * 64
    try:
        write_stage_manifest(
            manifest_path,
            type(manifest).model_validate({**manifest.model_dump(mode="json"), "inputs": inputs}),
        )
        runner = _StageRunner()
        with pytest.raises(SecAwareError):
            _stage_run(config, store, runner, force=True)
        assert runner.analysis_calls == 0
        assert _oracle_bytes(store) == committed
    finally:
        manifest_path.write_bytes(previous)


@pytest.mark.parametrize("drift", ("standalone_request", "nested_request", "terminal_request"))
def test_confirmation_oracle_rejects_request_closure_drift_pre_analyzer(
    _generated_confirmation_store, tmp_path: Path, drift: str
) -> None:
    config, store = _copied_store(_generated_confirmation_store, tmp_path)
    requests = list(
        read_jsonl(
            store.path("generation", "confirmation_requests.jsonl"),
            __import__(
                "secaware.schema.generation", fromlist=["GenerationRequestRecord"]
            ).GenerationRequestRecord,
            required=True,
            allow_empty=False,
        )
    )
    executions = list(
        read_jsonl(
            store.path("generation", "confirmation_execution.jsonl"),
            AssignmentExecutionRecord,
            required=True,
            allow_empty=False,
        )
    )
    codes = list(
        read_jsonl(
            store.path("generation", "confirmation_code.jsonl"),
            CanonicalGeneratedCodeRecord,
            required=True,
            allow_empty=True,
        )
    )
    replacements: dict[str, tuple[object, ...]] = {}
    if drift == "standalone_request":
        replacements["generation/confirmation_requests.jsonl"] = tuple(requests[1:])
    elif drift == "nested_request":
        original = codes[0]
        other = next(
            request for request in requests if request.assignment_id != original.assignment_id
        )
        codes[0] = canonical_generated_code_from_request(
            other,
            original.code,
            original.generation_provenance,
            provider_result_sha256=original.provider_result_sha256,
            provider_usage_sha256=original.provider_usage_sha256,
            provider_runtime_sha256=original.provider_runtime_sha256,
            provider_policy_sha256=original.provider_policy_sha256,
            provider_attempt_count=original.provider_attempt_count,
        )
        replacements["generation/confirmation_code.jsonl"] = tuple(codes)
    else:
        original = executions[0]
        other_request = next(
            request for request in requests if request.assignment_id != original.assignment_id
        )
        executions[0] = AssignmentExecutionRecord.from_content(
            assignment_id=original.assignment_id,
            request_id=other_request.request_id,
            status=AssignmentExecutionStatus.TERMINAL_NO_CODE,
            provider_result_sha256=original.provider_result_sha256,
            provider_provenance_sha256=original.provider_provenance_sha256,
            provider_runtime_sha256=original.provider_runtime_sha256,
            provider_policy_sha256=original.provider_policy_sha256,
            usage_sha256=original.usage_sha256,
            attempt_count=original.attempt_count,
            code_id=None,
            code_sha256=None,
            terminal_reason="content_filter",
        )
        codes = [item for item in codes if item.assignment_id != original.assignment_id]
        replacements["generation/confirmation_execution.jsonl"] = tuple(executions)
        replacements["generation/confirmation_code.jsonl"] = tuple(codes)
    _rewrite_producer_outputs(store, "generate-confirmation", replacements)
    runner = _StageRunner()
    with pytest.raises(SecAwareError):
        _stage_run(config, store, runner, force=True)
    assert runner.analysis_calls == 0


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


def test_confirmation_oracle_adapter_drift_aborts_and_preserves_commit(
    _generated_confirmation_store, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, store = _generated_confirmation_store
    committed = _committed_oracle_bytes(config, store)

    def drift_on_first_analysis(call: int) -> None:
        if call == 1:
            monkeypatch.setattr(
                oracle_aggregator,
                "parse_semgrep_report",
                lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("drift")),
            )

    runner = _StageRunner(on_analysis=drift_on_first_analysis)
    with pytest.raises(SecAwareError) as captured:
        _stage_run(config, store, runner, force=True)
    assert captured.value.code in {ErrorCode.CONTRACT, ErrorCode.ANALYZER_FAILED}
    assert runner.analysis_calls == 1
    assert _oracle_bytes(store) == committed


@pytest.mark.parametrize(
    "global_name",
    (
        "OracleCodeAnalysis",
        "AnalyzerReport",
        "LocatedAnalyzerFinding",
        "AnalyzerFindingRecord",
        "AnalyzerProvenanceRecord",
    ),
)
def test_confirmation_oracle_runtime_contract_binds_analysis_dto_globals(
    monkeypatch: pytest.MonkeyPatch, global_name: str
) -> None:
    baseline = confirmation_oracle_module.confirmation_oracle_runtime_callable_contract()
    replacement = type(f"Forged{global_name}", (), {})
    monkeypatch.setattr(oracle_aggregator, global_name, replacement)
    changed = confirmation_oracle_module.confirmation_oracle_runtime_callable_contract()
    assert changed != baseline


def test_confirmation_oracle_rejects_in_call_forged_analysis_dto_and_preserves_commit(
    _generated_confirmation_store, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, store = _generated_confirmation_store
    committed = _committed_oracle_bytes(config, store)
    trusted_analysis_type = oracle_aggregator.OracleCodeAnalysis
    fabricated = AnalyzerFindingRecord(
        schema_version="1.0",
        analyzer="semgrep",
        rule_id="forged.rule",
        cwe="CWE-999",
        severity="high",
        confidence="high",
        line=1,
        column=1,
        end_line=1,
        end_column=2,
        message="fabricated finding",
    )

    def drift_on_first_analysis(call: int) -> None:
        if call != 1:
            return

        def forged_analysis(**kwargs):
            kwargs["security_label"] = SecurityLabel.INSECURE
            kwargs["severity"] = "high"
            kwargs["findings"] = (fabricated,)
            return trusted_analysis_type(**kwargs)

        monkeypatch.setattr(oracle_aggregator, "OracleCodeAnalysis", forged_analysis)

    runner = _StageRunner(on_analysis=drift_on_first_analysis)
    with pytest.raises(SecAwareError):
        _stage_run(config, store, runner, force=True)
    assert _oracle_bytes(store) == committed


def test_confirmation_oracle_runner_method_drift_aborts_and_preserves_commit(
    _generated_confirmation_store, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, store = _generated_confirmation_store
    committed = _committed_oracle_bytes(config, store)
    original = _StageRunner.__call__

    def drift_on_first_analysis(call: int) -> None:
        if call == 1:

            def changed(self, *args, **kwargs):
                return original(self, *args, **kwargs)

            monkeypatch.setattr(_StageRunner, "__call__", changed)

    runner = _StageRunner(on_analysis=drift_on_first_analysis)
    with pytest.raises(SecAwareError) as captured:
        _stage_run(config, store, runner, force=True)
    assert captured.value.code is ErrorCode.CONTRACT
    assert _oracle_bytes(store) == committed


def test_confirmation_oracle_pre_capture_adapter_drift_invalidates_skip(
    _generated_confirmation_store, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, store = _generated_confirmation_store
    _committed_oracle_bytes(config, store)
    original = oracle_aggregator.parse_semgrep_report

    def wrapped(*args, **kwargs):
        return original(*args, **kwargs)

    monkeypatch.setattr(oracle_aggregator, "parse_semgrep_report", wrapped)
    runner = _StageRunner()
    _stage_run(config, store, runner, force=False)
    assert runner.analysis_calls == 2


@pytest.mark.parametrize(
    "stage_name",
    (
        "IMPORT-FUNCTIONAL-OUTCOMES",
        "analyze-jci",
        "reporting-secondary",
        "effects",
    ),
)
def test_confirmation_oracle_rejects_manifest_only_future_stage_casefold_exact_or_prefix(
    _generated_confirmation_store, stage_name: str
) -> None:
    _config, store = _generated_confirmation_store
    future = store.path(".stages", f"{stage_name}.json")
    future.write_text("{}\n", encoding="utf-8")
    try:
        with pytest.raises(SecAwareError):
            confirmation_oracle_module._guard_no_future_artifacts(store)
    finally:
        future.unlink(missing_ok=True)


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
    monkeypatch.setattr("secaware.oracle.aggregator.validate_analyzer_runtime", lambda: object())
    first = _confirmation_code(task_id="task-confirmation-a")[2]
    second = _confirmation_code(task_id="task-confirmation-b")[2]
    policy = load_policy_bundle(_POLICY_LOCK)
    forward = run_oracle_batch((first, second), policy, runner=FakeRunner())
    reverse = run_oracle_batch((second, first), policy, runner=FakeRunner())
    assert forward == reverse
    assert [item.request_id for item in forward] == sorted((first.request_id, second.request_id))


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

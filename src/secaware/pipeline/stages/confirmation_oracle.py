"""Independent, assignment-bound Oracle publication for randomized confirmation."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
from typing import TypeVar

from pydantic import BaseModel

from secaware.config import AppConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.io.run_store import RunStore
from secaware.oracle import aggregator as oracle_aggregator
from secaware.oracle.aggregator import (
    AnalyzerRunner,
    OracleCodeAnalysis,
    OracleCodeInput,
)
from secaware.oracle.runner import run_analyzer_process, validate_analyzer_runtime
from secaware.oracle.policy import load_policy_bundle
from secaware.oracle.strict_json import load_strict_json_bytes
from secaware.pipeline.bounded_traversal import BoundedTraversalError, iter_bounded_tree
from secaware.pipeline.artifact import canonical_sha256
from secaware.pipeline.jsonl_stage import (
    JsonlOutputSpec,
    execute_jsonl_stage_transaction,
)
from secaware.pipeline.manifest import StageManifest
from secaware.pipeline.preflight import run_oracle_preflight
from secaware.pipeline.stages import confirmation_generation as generation_stage
from secaware.pipeline.stages import randomization as randomization_stage
from secaware.pipeline.stages.confirmation_generation import CONFIRMATION_GENERATION_OUTPUTS
from secaware.pipeline.stages.confirmation_generation import (
    _runtime_callable_descriptor,
    validate_confirmation_generation_bundle,
)
from secaware.pipeline.stages.fci_discovery import FCI_DISCOVERY_OUTPUTS
from secaware.pipeline.stages.prompt_variants import (
    PROMPT_VARIANT_OUTPUTS,
    validate_prompt_variant_artifact_bundle,
)
from secaware.pipeline.stages.randomization import (
    RANDOMIZATION_OUTPUTS,
    validate_randomization_artifact_bundle,
)
from secaware.schema.common import model_shape_is_intact
from secaware.schema.experiments import (
    AssignmentExecutionRecord,
    AssignmentExecutionStatus,
    AssignmentRecord,
    ConfirmationProtocolInstanceRecord,
    ConfirmationProtocolRecord,
    FunctionalOutcomeContractRecord,
    PromptVariantRecord,
    PreRandomizationExclusionRecord,
    RandomizationManifestRecord,
    TargetInstanceRecord,
    TargetSpecRecord,
)
from secaware.intervention.attestation import PromptRoleAttestationRecord
from secaware.schema.causal import FrozenHypothesisRecord
from secaware.schema.generation import (
    GenerationRequestRecord,
    provider_provenance_sha256,
)
from secaware.schema.oracle import OracleRecord
from secaware.schema.prompt_extraction import PromptExtractionProposalRecord
from secaware.schema.records import CanonicalGeneratedCodeRecord, PromptRecord
from secaware.schema.tsg import PromptTSGRecord
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256


_STAGE = "run-oracle-confirmation"
_OUTPUT_NAME = "confirmation_oracle.jsonl"
_MAX_RECORDS = 100_000
_MAX_INPUT_FILE_BYTES = 256 * 1024 * 1024
_MAX_COMBINED_INPUT_BYTES = 768 * 1024 * 1024
_MAX_LINE_BYTES = 8 * 1024 * 1024
_MAX_TOTAL_CODE_BYTES = 1_000_000_000
_FATAL = (MemoryError, KeyboardInterrupt, SystemExit)
_MAX_TRAVERSAL_ENTRIES = 100_000
_MAX_TRAVERSAL_DEPTH = 32
_MAX_RELATIVE_PATH_CHARS = 4096
_MAX_NAME_CHARS = 255
_FUTURE_DIRS = frozenset({"analysis", "effects", "reports", "report", "jci", "rfci", "mechanisms"})
_FUTURE_STAGE_NAMES = frozenset(
    {
        "import-functional-outcomes",
        "confirm",
        "analyze-jci",
        "analyze-rfci",
        "effects",
        "estimate-effects",
        "mechanisms",
        "report",
        "reporting",
        "jci",
        "rfci",
    }
)
_FUTURE_STAGE_PREFIXES = tuple(name + "-" for name in sorted(_FUTURE_STAGE_NAMES))
_PUBLIC_MESSAGES = {
    ErrorCode.CONFIG: "confirmation Oracle configuration is invalid",
    ErrorCode.CONTRACT: "confirmation Oracle artifact validation failed",
    ErrorCode.ANALYZER_MISSING: "analyzer executable is unavailable",
    ErrorCode.ANALYZER_FAILED: "analyzer execution failed",
    ErrorCode.ANALYZER_INVALID_OUTPUT: "analyzer output is invalid",
    ErrorCode.POLICY_MISMATCH: "analyzer policy or version does not match",
    ErrorCode.MANIFEST_CONFLICT: "confirmation Oracle trust verification failed",
}


@dataclass(frozen=True, slots=True, repr=False)
class _FileSnapshot:
    path: Path
    sha256: str
    identity: tuple[int, int, int, int, int, int]


@dataclass(frozen=True, slots=True, repr=False)
class _InputSnapshot:
    files: tuple[_FileSnapshot, ...]
    prompts: tuple[PromptRecord, ...]
    attestations: tuple[PromptRoleAttestationRecord, ...]
    contracts: tuple[FunctionalOutcomeContractRecord, ...]
    source_proposals: tuple[PromptExtractionProposalRecord, ...]
    source_graphs: tuple[PromptTSGRecord, ...]
    task4_groups: tuple[tuple[BaseModel, ...], ...]
    targets: tuple[TargetSpecRecord, ...]
    target_instances: tuple[TargetInstanceRecord, ...]
    protocols: tuple[ConfirmationProtocolRecord, ...]
    protocol_instances: tuple[ConfirmationProtocolInstanceRecord, ...]
    variants: tuple[PromptVariantRecord, ...]
    exclusions: tuple[PreRandomizationExclusionRecord, ...]
    hypotheses: tuple[FrozenHypothesisRecord, ...]
    randomization_manifest: RandomizationManifestRecord
    assignments: tuple[AssignmentRecord, ...]
    requests: tuple[GenerationRequestRecord, ...]
    executions: tuple[AssignmentExecutionRecord, ...]
    codes: tuple[CanonicalGeneratedCodeRecord, ...]


@dataclass(frozen=True, slots=True)
class ConfirmationOracleStageResult:
    assignment_count: int
    generated_count: int
    terminal_no_code_count: int
    oracle_count: int


@dataclass(frozen=True, slots=True, repr=False)
class _AnalyzerRuntime:
    runner: AnalyzerRunner
    validator: Callable[[], object]


def _analyzer_runtime_from_frozen_config(_config: object) -> _AnalyzerRuntime:
    return _AnalyzerRuntime(
        runner=run_analyzer_process,
        validator=validate_analyzer_runtime,
    )


_ANALYZER_RUNTIME_FACTORY = _analyzer_runtime_from_frozen_config


_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _error(message: str, *, code: ErrorCode = ErrorCode.CONTRACT) -> SecAwareError:
    return SecAwareError(
        code=code,
        stage=_STAGE,
        message=message,
        details={},
        retryable=False,
    )


def _public_error(code: ErrorCode) -> SecAwareError:
    if code not in _PUBLIC_MESSAGES:
        code = ErrorCode.ANALYZER_FAILED
    return _error(_PUBLIC_MESSAGES[code], code=code)


def _clear_exception(error: BaseException | None) -> None:
    if error is None:
        return
    try:
        error.__traceback__ = None
        error.__cause__ = None
        error.__context__ = None
    except BaseException:
        pass


def _trusted_records(
    values: Iterable[_ModelT], model: type[_ModelT], *, allow_empty: bool
) -> tuple[_ModelT, ...]:
    records: list[_ModelT] = []
    result: tuple[_ModelT, ...] = ()
    value: object = None
    try:
        if isinstance(values, (str, bytes, Mapping)):
            raise TypeError
        for index, value in enumerate(values):
            if index >= _MAX_RECORDS:
                raise ValueError
            if type(value) is not model or not model_shape_is_intact(value):
                raise TypeError
            records.append(
                model.model_validate(
                    value.model_dump(mode="python", round_trip=True, warnings=False)
                )
            )
            value = None
        if not records and not allow_empty:
            raise ValueError
        result = tuple(records)
    except _FATAL:
        raise
    except Exception:
        raise _error("confirmation Oracle relation failed validation") from None
    finally:
        values = ()
        model = BaseModel  # type: ignore[assignment]
        value = None
        records.clear()
    return result


def validate_confirmation_oracle_coverage(
    assignments: Iterable[AssignmentRecord],
    executions: Iterable[AssignmentExecutionRecord],
    codes: Iterable[CanonicalGeneratedCodeRecord],
    oracles: Iterable[OracleRecord],
) -> ConfirmationOracleStageResult:
    """Require one Oracle per GENERATED assignment and none for terminal-no-code."""

    trusted_assignments: tuple[AssignmentRecord, ...] = ()
    trusted_executions: tuple[AssignmentExecutionRecord, ...] = ()
    trusted_codes: tuple[CanonicalGeneratedCodeRecord, ...] = ()
    trusted_oracles: tuple[OracleRecord, ...] = ()
    result: ConfirmationOracleStageResult | None = None
    try:
        trusted_assignments = _trusted_records(assignments, AssignmentRecord, allow_empty=False)
        trusted_executions = _trusted_records(
            executions, AssignmentExecutionRecord, allow_empty=False
        )
        trusted_codes = _trusted_records(codes, CanonicalGeneratedCodeRecord, allow_empty=True)
        trusted_oracles = _trusted_records(oracles, OracleRecord, allow_empty=True)
        if (
            tuple(item.assignment_id for item in trusted_executions)
            != tuple(sorted(item.assignment_id for item in trusted_executions))
            or tuple(item.assignment_id or "" for item in trusted_codes)
            != tuple(sorted(item.assignment_id or "" for item in trusted_codes))
            or tuple(item.request_id for item in trusted_oracles)
            != tuple(sorted(item.request_id for item in trusted_oracles))
        ):
            raise ValueError

        assignment_by_id = {item.assignment_id: item for item in trusted_assignments}
        execution_by_id = {item.assignment_id: item for item in trusted_executions}
        code_by_id = {item.assignment_id: item for item in trusted_codes}
        oracle_by_request = {item.request_id: item for item in trusted_oracles}
        if (
            len(assignment_by_id) != len(trusted_assignments)
            or len(execution_by_id) != len(trusted_executions)
            or len(code_by_id) != len(trusted_codes)
            or len(oracle_by_request) != len(trusted_oracles)
            or set(assignment_by_id) != set(execution_by_id)
        ):
            raise ValueError
        generated = {
            assignment_id
            for assignment_id, execution in execution_by_id.items()
            if execution.status is AssignmentExecutionStatus.GENERATED
        }
        if set(code_by_id) != generated:
            raise ValueError
        if set(oracle_by_request) != {code.request_id for code in trusted_codes}:
            raise ValueError

        for assignment_id in sorted(assignment_by_id):
            assignment = assignment_by_id[assignment_id]
            execution = execution_by_id[assignment_id]
            code = code_by_id.get(assignment_id)
            if code is None:
                if execution.status is not AssignmentExecutionStatus.TERMINAL_NO_CODE:
                    raise ValueError
                continue
            unit = assignment.experimental_unit
            request = code.generation_request
            oracle = oracle_by_request.get(code.request_id)
            if oracle is None or execution.status is not AssignmentExecutionStatus.GENERATED:
                raise ValueError
            expected_coordinates = (
                (code.condition, "confirm_arm"),
                (code.assignment_id, assignment.assignment_id),
                (code.hypothesis_id, unit.hypothesis_id),
                (code.target_spec_id, assignment.target_spec_id),
                (code.target_instance_id, assignment.target_instance_id),
                (code.arm_protocol_id, assignment.arm_protocol_id),
                (code.protocol_instance_id, assignment.protocol_instance_id),
                (code.variant_id, assignment.variant_id),
                (code.arm_role, assignment.arm_role),
                (code.model_id, unit.model_id),
                (code.seed_id, assignment.seed_id),
                (execution.request_id, code.request_id),
                (execution.code_id, code.code_id),
                (execution.code_sha256, code.code_sha256),
                (execution.provider_result_sha256, code.provider_result_sha256),
                (execution.usage_sha256, code.provider_usage_sha256),
                (execution.provider_runtime_sha256, code.provider_runtime_sha256),
                (execution.provider_policy_sha256, code.provider_policy_sha256),
                (execution.attempt_count, code.provider_attempt_count),
                (
                    execution.provider_provenance_sha256,
                    provider_provenance_sha256(code.generation_provenance),
                ),
                (request.assignment_id, assignment.assignment_id),
                (request.request_id, code.request_id),
            )
            oracle_coordinates = (
                (oracle.condition, "confirm_arm"),
                (oracle.request_id, code.request_id),
                (oracle.code_id, code.code_id),
                (oracle.code_sha256, code.code_sha256),
                (oracle.prompt_id, code.prompt_id),
                (oracle.hypothesis_id, code.hypothesis_id),
                (oracle.assignment_id, code.assignment_id),
                (oracle.target_spec_id, code.target_spec_id),
                (oracle.target_instance_id, code.target_instance_id),
                (oracle.arm_protocol_id, code.arm_protocol_id),
                (oracle.protocol_instance_id, code.protocol_instance_id),
                (oracle.variant_id, code.variant_id),
                (oracle.arm_role, code.arm_role),
                (oracle.model_id, code.model_id),
                (oracle.seed_id, code.seed_id),
            )
            if any(actual != expected for actual, expected in expected_coordinates):
                raise ValueError
            if any(actual != expected for actual, expected in oracle_coordinates):
                raise ValueError
        result = ConfirmationOracleStageResult(
            assignment_count=len(trusted_assignments),
            generated_count=len(trusted_codes),
            terminal_no_code_count=len(trusted_assignments) - len(trusted_codes),
            oracle_count=len(trusted_oracles),
        )
    except _FATAL:
        raise
    except SecAwareError:
        raise
    except Exception:
        raise _error("confirmation Oracle relation failed validation") from None
    finally:
        assignments = ()
        executions = ()
        codes = ()
        oracles = ()
        trusted_assignments = ()
        trusted_executions = ()
        trusted_codes = ()
        trusted_oracles = ()
        assignment_by_id = {}
        execution_by_id = {}
        code_by_id = {}
        oracle_by_request = {}
        generated = set()
        assignment = None
        execution = None
        code = None
        request = None
        oracle = None
    if result is None:  # pragma: no cover
        raise _error("confirmation Oracle relation failed validation")
    return result


def _bind_oracle_analyses(
    codes: Sequence[CanonicalGeneratedCodeRecord],
    analyses: Sequence[OracleCodeAnalysis],
) -> tuple[OracleRecord, ...]:
    try:
        code_by_request = {item.request_id: item for item in codes}
        analysis_by_request = {item.request_id: item for item in analyses}
        if (
            len(code_by_request) != len(codes)
            or len(analysis_by_request) != len(analyses)
            or set(code_by_request) != set(analysis_by_request)
        ):
            raise ValueError
        records: list[OracleRecord] = []
        for request_id in sorted(code_by_request):
            code = code_by_request[request_id]
            analysis = analysis_by_request[request_id]
            if (
                analysis.code_id != code.code_id
                or analysis.code_sha256 != code.code_sha256
                or analysis.prompt_id != code.prompt_id
                or analysis.model_id != code.model_id
                or analysis.seed_id != code.seed_id
            ):
                raise ValueError
            records.append(
                OracleRecord(
                    schema_version="1.2",
                    request_id=code.request_id,
                    code_id=code.code_id,
                    code_sha256=code.code_sha256,
                    prompt_id=code.prompt_id,
                    condition="confirm_arm",
                    model_id=code.model_id,
                    seed_id=code.seed_id,
                    hypothesis_id=code.hypothesis_id,
                    assignment_id=code.assignment_id,
                    target_spec_id=code.target_spec_id,
                    target_instance_id=code.target_instance_id,
                    arm_protocol_id=code.arm_protocol_id,
                    protocol_instance_id=code.protocol_instance_id,
                    variant_id=code.variant_id,
                    arm_role=code.arm_role,
                    parse_ok=analysis.parse_ok,
                    functional_ok=analysis.functional_ok,
                    security_label=analysis.security_label,
                    evaluability=analysis.evaluability,
                    severity=analysis.severity,
                    findings=analysis.findings,
                    analyzers=analysis.analyzers,
                )
            )
        return tuple(records)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _error("confirmation Oracle analysis binding failed validation") from None
    finally:
        codes = ()
        analyses = ()
        code_by_request = {}
        analysis_by_request = {}
        records = []
        request_id = ""
        code = None
        analysis = None


def _validate_upstream_bundles(
    snapshot: _InputSnapshot,
    config: AppConfig,
    *,
    prompt_variant_validator=validate_prompt_variant_artifact_bundle,
    randomization_validator=validate_randomization_artifact_bundle,
    generation_validator=validate_confirmation_generation_bundle,
    block_builder=randomization_stage.build_randomization_blocks,
    planner=generation_stage.plan_confirmation_requests,
    provenance_hasher=provider_provenance_sha256,
) -> None:
    """Replay the complete Task-4/5/6 provenance before trusting generated code."""

    prompt_variant_validator(
        config,
        prompts=snapshot.prompts,
        attestations=snapshot.attestations,
        contracts=snapshot.contracts,
        source_proposals=snapshot.source_proposals,
        source_graphs=snapshot.source_graphs,
        hypotheses=snapshot.hypotheses,
        groups=snapshot.task4_groups,
    )
    randomization_validator(
        snapshot.randomization_manifest,
        snapshot.assignments,
        target_specs=snapshot.targets,
        target_instances=snapshot.target_instances,
        protocols=snapshot.protocols,
        protocol_instances=snapshot.protocol_instances,
        variants=snapshot.variants,
        exclusions=snapshot.exclusions,
        hypotheses=snapshot.hypotheses,
        confirmation_seeds=tuple(config.generation.confirmation_seeds),
        global_seed=config.run.random_seed,
        randomization_config=config.randomization,
        block_builder=block_builder,
    )
    generation_validator(
        snapshot.randomization_manifest,
        snapshot.assignments,
        snapshot.variants,
        config,
        snapshot.requests,
        snapshot.executions,
        snapshot.codes,
        planner=planner,
        provenance_hasher=provenance_hasher,
    )


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
    )


def _read_snapshot(path: Path, *, allow_empty: bool) -> tuple[bytes, _FileSnapshot]:
    descriptor = -1
    buffer = bytearray()
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > _MAX_INPUT_FILE_BYTES
            or (not allow_empty and before.st_size < 1)
        ):
            raise ValueError
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if _identity(opened) != _identity(before):
            raise ValueError
        digest = hashlib.sha256()
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise ValueError
            buffer.extend(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        after_path = path.lstat()
        if _identity(after) != _identity(opened) or _identity(after_path) != _identity(opened):
            raise ValueError
        return bytes(buffer), _FileSnapshot(path, digest.hexdigest(), _identity(after_path))
    except _FATAL:
        raise
    except Exception:
        raise _error("confirmation Oracle input snapshot failed validation") from None
    finally:
        buffer.clear()
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _parse_jsonl(payload: bytes, model: type[_ModelT], *, allow_empty: bool) -> tuple[_ModelT, ...]:
    records: list[_ModelT] = []
    result: tuple[_ModelT, ...] = ()
    line = b""
    try:
        if len(payload) > _MAX_INPUT_FILE_BYTES:
            raise ValueError
        for line in payload.splitlines():
            if not line.strip():
                continue
            if len(line) > _MAX_LINE_BYTES:
                raise ValueError
            records.append(model.model_validate(load_strict_json_bytes(line)))
            if len(records) > _MAX_RECORDS:
                raise ValueError
        if not records and not allow_empty:
            raise ValueError
        result = tuple(records)
    except _FATAL:
        raise
    except Exception:
        raise _error("confirmation Oracle input artifact failed validation") from None
    finally:
        payload = b""
        line = b""
        records.clear()
    return result


def _parse_manifest(payload: bytes, expected_stage: str) -> StageManifest:
    try:
        manifest = StageManifest.model_validate(load_strict_json_bytes(payload))
        if manifest.stage != expected_stage:
            raise ValueError
        return manifest
    except _FATAL:
        raise
    except Exception:
        raise _error("confirmation Oracle producer manifest failed validation") from None
    finally:
        payload = b""
        expected_stage = ""


def _guard_no_future_artifacts(store: RunStore, *, traversal=iter_bounded_tree) -> None:
    try:
        for entry in traversal(
            store.root,
            max_entries=_MAX_TRAVERSAL_ENTRIES,
            max_depth=_MAX_TRAVERSAL_DEPTH,
            max_relative_path_chars=_MAX_RELATIVE_PATH_CHARS,
            max_name_chars=_MAX_NAME_CHARS,
        ):
            if not entry.is_file:
                continue
            parts = entry.relative_path.replace("\\", "/").split("/")
            if parts[0].casefold() in _FUTURE_DIRS:
                raise ValueError
            if (
                len(parts) == 2
                and parts[0].casefold() == ".stages"
                and Path(parts[1]).suffix.casefold() == ".json"
            ):
                stage_name = Path(parts[1]).stem.casefold()
                if stage_name in _FUTURE_STAGE_NAMES or any(
                    stage_name.startswith(prefix) for prefix in _FUTURE_STAGE_PREFIXES
                ):
                    raise ValueError
    except _FATAL:
        raise
    except BoundedTraversalError:
        raise _error("future analysis artifact traversal failed validation") from None
    except Exception:
        raise _error("future analysis artifact exists before confirmation Oracle") from None


def _run_confirmation_oracle_stage(
    config: AppConfig,
    store: RunStore,
    *,
    force: bool,
    analyzer_runtime: _AnalyzerRuntime,
    runtime_callables: Mapping[str, object],
    runtime_contract: Mapping[str, Mapping[str, str]],
    validate_only: bool = False,
) -> ConfirmationOracleStageResult:
    analyzer_runtime_refs = {
        "runner": analyzer_runtime.runner,
        "validator": analyzer_runtime.validator,
    }
    analyzer_runtime_contract = {
        name: _runtime_callable_descriptor(value)
        for name, value in sorted(analyzer_runtime_refs.items())
    }

    def verify_runtime_bundle() -> None:
        current = _confirmation_oracle_runtime_callables()
        if (
            tuple(sorted(current)) != tuple(sorted(runtime_callables))
            or any(current[name] is not value for name, value in runtime_callables.items())
            or {
                name: _runtime_callable_descriptor(value) for name, value in sorted(current.items())
            }
            != runtime_contract
            or analyzer_runtime.runner is not analyzer_runtime_refs["runner"]
            or analyzer_runtime.validator is not analyzer_runtime_refs["validator"]
            or {
                name: _runtime_callable_descriptor(value)
                for name, value in sorted(analyzer_runtime_refs.items())
            }
            != analyzer_runtime_contract
        ):
            raise _error("confirmation Oracle runtime callable bundle changed")

    verify_runtime_bundle()
    if (
        type(config) is not AppConfig
        or type(store) is not RunStore
        or store.config != config
        or not runtime_callables["input.model_shape_is_intact"](config)
        or type(force) is not bool
        or type(validate_only) is not bool
        or type(analyzer_runtime) is not _AnalyzerRuntime
        or not callable(analyzer_runtime.runner)
        or not callable(analyzer_runtime.validator)
    ):
        raise _error("confirmation Oracle configuration failed validation", code=ErrorCode.CONFIG)
    effective_config = AppConfig.model_validate(config.model_dump(mode="json"))
    effective_store = runtime_callables["input.run_store_factory"](effective_config)
    if effective_store.root != store.root:
        raise _error("confirmation Oracle configuration failed validation", code=ErrorCode.CONFIG)

    prompt_path = effective_store.path("inputs", "prompts.jsonl")
    attestation_path = Path(effective_config.data.prompt_attestations_path)
    contract_path = (
        Path(effective_config.data.functional_outcome_contracts_path)
        if effective_config.data.functional_outcome_contracts_path is not None
        else None
    )
    extraction_paths = (
        effective_store.path("tsg", "prompt_extraction_proposals.jsonl"),
        effective_store.path("tsg", "prompt_tsg.jsonl"),
    )
    task4_paths = tuple(
        effective_store.path("interventions", name) for name, _model in PROMPT_VARIANT_OUTPUTS
    )
    task5_paths = tuple(
        effective_store.path("interventions", name) for name, _model in RANDOMIZATION_OUTPUTS
    )
    fci_paths = tuple(
        effective_store.path("discovery", name) for name, _model in FCI_DISCOVERY_OUTPUTS
    )
    hypothesis_path = next(path for path in fci_paths if path.name == "hypotheses_frozen.jsonl")
    task6_paths = tuple(
        effective_store.path("generation", name) for name, _model in CONFIRMATION_GENERATION_OUTPUTS
    )
    manifest_paths = (
        effective_store.path(".stages", "extract-prompt-tsg.json"),
        effective_store.path(".stages", "build-confirmation-variants.json"),
        effective_store.path(".stages", "fci-discovery.json"),
        effective_store.path(".stages", "randomize-confirmation.json"),
        effective_store.path(".stages", "generate-confirmation.json"),
    )
    verify_runtime_bundle()
    initial_policy = (
        runtime_callables["preflight.load_policy_bundle"](effective_config.oracle.policy_lock_path)
        if validate_only
        else runtime_callables["preflight.run_oracle_preflight"](
            effective_config.oracle,
            runner=analyzer_runtime.runner,
            runtime_validator=analyzer_runtime.validator,
        )
    )
    verify_runtime_bundle()
    effective_policy_sha256 = canonical_sha256(
        {
            "policy_sha256": initial_policy.combined_sha256,
            "semgrep_executable": effective_config.oracle.semgrep_executable,
            "bandit_executable": effective_config.oracle.bandit_executable,
            "semgrep_version": initial_policy.semgrep_version,
            "bandit_version": initial_policy.bandit_version,
            "analyzer_runtime": analyzer_runtime_contract,
            "runtime_factory": runtime_contract["runtime.analyzer_factory"],
        }
    )
    policy_paths = (
        Path(effective_config.oracle.policy_lock_path),
        initial_policy.semgrep_rules_path,
        initial_policy.bandit_config_path,
        initial_policy.bandit_metadata_path,
    )
    inputs = (
        prompt_path,
        attestation_path,
        *((contract_path,) if contract_path is not None else ()),
        *extraction_paths,
        manifest_paths[0],
        *task4_paths,
        manifest_paths[1],
        hypothesis_path,
        manifest_paths[2],
        *task5_paths,
        manifest_paths[3],
        *task6_paths,
        manifest_paths[4],
        *policy_paths,
    )
    output = effective_store.path("oracle", _OUTPUT_NAME)
    output_spec = runtime_callables["transaction.jsonl_output_spec"](
        output,
        OracleRecord,
        require_nonempty=False,
        max_records=_MAX_RECORDS,
        max_line_chars=_MAX_LINE_BYTES,
        max_total_chars=_MAX_INPUT_FILE_BYTES,
    )
    snapshot: _InputSnapshot | None = None

    def capture_input_snapshot() -> tuple[str, ...]:
        nonlocal snapshot
        verify_runtime_bundle()
        if snapshot is not None:
            raise _error("confirmation Oracle input snapshot failed validation")
        runtime_callables["input.guard_no_future_artifacts"](
            effective_store, traversal=runtime_callables["input.bounded_tree"]
        )
        payloads: list[bytes] = []
        files: list[_FileSnapshot] = []
        combined = 0
        try:
            empty_task4_paths = {
                path
                for path, (name, _model) in zip(task4_paths, PROMPT_VARIANT_OUTPUTS, strict=True)
                if name
                not in {
                    "target_specs.jsonl",
                    "target_instances.jsonl",
                    "confirmation_protocols.jsonl",
                    "confirmation_protocol_instances.jsonl",
                }
            }
            for path in inputs:
                allow_empty = path in empty_task4_paths or path.name == "confirmation_code.jsonl"
                payload, file = runtime_callables["input.read_snapshot"](
                    path, allow_empty=allow_empty
                )
                combined += len(payload)
                if combined > _MAX_COMBINED_INPUT_BYTES:
                    raise _error("confirmation Oracle input resource limit exceeded")
                payloads.append(payload)
                files.append(file)
            payload_by_path = dict(zip(inputs, payloads, strict=True))
            runtime_callables["input.parse_manifest"](
                payload_by_path[manifest_paths[0]], "extract-prompt-tsg"
            )
            runtime_callables["input.parse_manifest"](
                payload_by_path[manifest_paths[1]], "build-confirmation-variants"
            )
            runtime_callables["input.parse_manifest"](
                payload_by_path[manifest_paths[2]], "fci-discovery"
            )
            runtime_callables["input.parse_manifest"](
                payload_by_path[manifest_paths[3]], "randomize-confirmation"
            )
            runtime_callables["input.parse_manifest"](
                payload_by_path[manifest_paths[4]], "generate-confirmation"
            )
            parser = runtime_callables["input.parse_jsonl"]
            prompts = parser(payload_by_path[prompt_path], PromptRecord, allow_empty=False)
            attestations = parser(
                payload_by_path[attestation_path],
                PromptRoleAttestationRecord,
                allow_empty=False,
            )
            contracts = (
                parser(
                    payload_by_path[contract_path],
                    FunctionalOutcomeContractRecord,
                    allow_empty=False,
                )
                if contract_path is not None
                else ()
            )
            source_proposals = parser(
                payload_by_path[extraction_paths[0]],
                PromptExtractionProposalRecord,
                allow_empty=False,
            )
            source_graphs = parser(
                payload_by_path[extraction_paths[1]], PromptTSGRecord, allow_empty=False
            )
            task4_groups = tuple(
                parser(
                    payload_by_path[path],
                    model,
                    allow_empty=name
                    not in {
                        "target_specs.jsonl",
                        "target_instances.jsonl",
                        "confirmation_protocols.jsonl",
                        "confirmation_protocol_instances.jsonl",
                    },
                )
                for path, (name, model) in zip(task4_paths, PROMPT_VARIANT_OUTPUTS, strict=True)
            )
            task4_by_name = {
                name: group
                for (name, _model), group in zip(PROMPT_VARIANT_OUTPUTS, task4_groups, strict=True)
            }
            targets = task4_by_name["target_specs.jsonl"]
            target_instances = task4_by_name["target_instances.jsonl"]
            protocols = task4_by_name["confirmation_protocols.jsonl"]
            protocol_instances = task4_by_name["confirmation_protocol_instances.jsonl"]
            variants = task4_by_name["prompt_variants.jsonl"]
            exclusions = task4_by_name["pre_randomization_exclusions.jsonl"]
            hypotheses = parser(
                payload_by_path[hypothesis_path], FrozenHypothesisRecord, allow_empty=False
            )
            task5_by_name = {
                name: parser(payload_by_path[path], model, allow_empty=False)
                for path, (name, model) in zip(task5_paths, RANDOMIZATION_OUTPUTS, strict=True)
            }
            randomization_records = task5_by_name["randomization_manifest.jsonl"]
            if len(randomization_records) != 1:
                raise _error("confirmation Oracle randomization manifest failed validation")
            assignments = task5_by_name["assignments.jsonl"]
            task6_by_name = {
                name: parser(
                    payload_by_path[path],
                    model,
                    allow_empty=name == "confirmation_code.jsonl",
                )
                for path, (name, model) in zip(
                    task6_paths, CONFIRMATION_GENERATION_OUTPUTS, strict=True
                )
            }
            requests = task6_by_name["confirmation_requests.jsonl"]
            executions = task6_by_name["confirmation_execution.jsonl"]
            codes = task6_by_name["confirmation_code.jsonl"]
            if sum(len(item.code.encode("utf-8")) for item in codes) > _MAX_TOTAL_CODE_BYTES:
                raise _error("confirmation Oracle code resource limit exceeded")
            snapshot = _InputSnapshot(
                files=tuple(files),
                prompts=prompts,
                attestations=attestations,
                contracts=contracts,
                source_proposals=source_proposals,
                source_graphs=source_graphs,
                task4_groups=task4_groups,
                targets=targets,
                target_instances=target_instances,
                protocols=protocols,
                protocol_instances=protocol_instances,
                variants=variants,
                exclusions=exclusions,
                hypotheses=hypotheses,
                randomization_manifest=randomization_records[0],
                assignments=assignments,
                requests=requests,
                executions=executions,
                codes=codes,
            )
            runtime_callables["validation.upstream_bundles"](
                snapshot,
                effective_config,
                prompt_variant_validator=runtime_callables[
                    "validation.prompt_variant_artifact_bundle"
                ],
                randomization_validator=runtime_callables[
                    "validation.randomization_artifact_bundle"
                ],
                generation_validator=runtime_callables["validation.confirmation_generation_bundle"],
                block_builder=runtime_callables["validation.randomization_block_builder"],
                planner=runtime_callables["validation.plan_confirmation_requests"],
                provenance_hasher=runtime_callables["validation.provider_provenance_sha256"],
            )
            verify_runtime_bundle()
            return tuple(item.sha256 for item in snapshot.files)
        finally:
            payloads.clear()
            files.clear()
            payload_by_path = {}
            payload = b""
            file = None
            prompts = ()
            attestations = ()
            contracts = ()
            source_proposals = ()
            source_graphs = ()
            task4_groups = ()
            task4_by_name = {}
            targets = ()
            target_instances = ()
            protocols = ()
            protocol_instances = ()
            variants = ()
            exclusions = ()
            hypotheses = ()
            randomization_records = ()
            task5_by_name = {}
            assignments = ()
            requests = ()
            executions = ()
            codes = ()
            task6_by_name = {}

    def verify_input_snapshot() -> None:
        verify_runtime_bundle()
        if snapshot is None:
            raise _error("confirmation Oracle input snapshot failed validation")
        runtime_callables["input.guard_no_future_artifacts"](
            effective_store, traversal=runtime_callables["input.bounded_tree"]
        )
        for expected in snapshot.files:
            payload, current = runtime_callables["input.read_snapshot"](
                expected.path, allow_empty=expected.identity[4] == 0
            )
            del payload
            if current != expected:
                raise _error("confirmation Oracle inputs changed during execution")
        runtime_callables["validation.upstream_bundles"](
            snapshot,
            effective_config,
            prompt_variant_validator=runtime_callables["validation.prompt_variant_artifact_bundle"],
            randomization_validator=runtime_callables["validation.randomization_artifact_bundle"],
            generation_validator=runtime_callables["validation.confirmation_generation_bundle"],
            block_builder=runtime_callables["validation.randomization_block_builder"],
            planner=runtime_callables["validation.plan_confirmation_requests"],
            provenance_hasher=runtime_callables["validation.provider_provenance_sha256"],
        )
        if not validate_only:
            final_policy = runtime_callables["preflight.run_oracle_preflight"](
                effective_config.oracle,
                runner=analyzer_runtime.runner,
                runtime_validator=analyzer_runtime.validator,
            )
            if final_policy.combined_sha256 != initial_policy.combined_sha256:
                raise _error(
                    "confirmation Oracle policy changed during execution",
                    code=ErrorCode.POLICY_MISMATCH,
                )
        verify_runtime_bundle()

    def build() -> tuple[tuple[OracleRecord, ...]]:
        verify_runtime_bundle()
        if snapshot is None:
            raise _error("confirmation Oracle input snapshot failed validation")
        if validate_only:
            raise _error(
                "committed confirmation Oracle failed trust verification",
                code=ErrorCode.MANIFEST_CONFLICT,
            )
        runtime_callables["validation.upstream_bundles"](
            snapshot,
            effective_config,
            prompt_variant_validator=runtime_callables["validation.prompt_variant_artifact_bundle"],
            randomization_validator=runtime_callables["validation.randomization_artifact_bundle"],
            generation_validator=runtime_callables["validation.confirmation_generation_bundle"],
            block_builder=runtime_callables["validation.randomization_block_builder"],
            planner=runtime_callables["validation.plan_confirmation_requests"],
            provenance_hasher=runtime_callables["validation.provider_provenance_sha256"],
        )
        execution_policy = runtime_callables["preflight.run_oracle_preflight"](
            effective_config.oracle,
            runner=analyzer_runtime.runner,
            runtime_validator=analyzer_runtime.validator,
        )
        if execution_policy.combined_sha256 != initial_policy.combined_sha256:
            raise _error(
                "confirmation Oracle policy changed before execution",
                code=ErrorCode.POLICY_MISMATCH,
            )
        if not snapshot.codes:
            records: tuple[OracleRecord, ...] = ()
        else:
            verify_runtime_bundle()
            code_input_type = runtime_callables["aggregate.oracle_code_input"]
            code_inputs = tuple(code_input_type.from_canonical(code) for code in snapshot.codes)
            analyses = runtime_callables["aggregate.run_oracle_code_batch"](
                code_inputs,
                execution_policy,
                semgrep_executable=effective_config.oracle.semgrep_executable,
                bandit_executable=effective_config.oracle.bandit_executable,
                timeout_seconds=effective_config.oracle.timeout_seconds,
                max_stdout_bytes=effective_config.oracle.max_stdout_bytes,
                max_stderr_bytes=effective_config.oracle.max_stderr_bytes,
                runner=analyzer_runtime.runner,
                runtime_validator=analyzer_runtime.validator,
            )
            verify_runtime_bundle()
            analyses = runtime_callables["aggregate.validate_code_analyses"](analyses)
            records = runtime_callables["aggregate.bind_oracle_analyses"](snapshot.codes, analyses)
        runtime_callables["relation.validate_confirmation_oracle_coverage"](
            snapshot.assignments, snapshot.executions, snapshot.codes, records
        )
        verify_runtime_bundle()
        return (records,)

    def validate_staged_outputs(groups: tuple[tuple[object, ...], ...]) -> None:
        verify_runtime_bundle()
        if snapshot is None or len(groups) != 1:
            raise _error("confirmation Oracle output bundle failed validation")
        runtime_callables["validation.upstream_bundles"](
            snapshot,
            effective_config,
            prompt_variant_validator=runtime_callables["validation.prompt_variant_artifact_bundle"],
            randomization_validator=runtime_callables["validation.randomization_artifact_bundle"],
            generation_validator=runtime_callables["validation.confirmation_generation_bundle"],
            block_builder=runtime_callables["validation.randomization_block_builder"],
            planner=runtime_callables["validation.plan_confirmation_requests"],
            provenance_hasher=runtime_callables["validation.provider_provenance_sha256"],
        )
        runtime_callables["relation.validate_confirmation_oracle_coverage"](
            snapshot.assignments,
            snapshot.executions,
            snapshot.codes,
            groups[0],
        )
        verify_runtime_bundle()

    producer_outputs = {
        "extract-prompt-tsg": extraction_paths,
        "build-confirmation-variants": task4_paths,
        "fci-discovery": fci_paths,
        "randomize-confirmation": task5_paths,
        "generate-confirmation": task6_paths,
    }
    with ExitStack() as stack:
        for producer_stage in sorted(producer_outputs):
            stack.enter_context(
                effective_store.hold_committed_output(
                    producer_stage,
                    producer_outputs[producer_stage],
                    expected_catalog_sha256=(
                        PROMPT_FEATURE_CATALOG_SHA256
                        if producer_stage in {"extract-prompt-tsg", "build-confirmation-variants"}
                        else None
                    ),
                )
            )
        verify_runtime_bundle()
        runtime_callables["transaction.execute_jsonl_stage_transaction"](
            effective_store,
            stage=_STAGE,
            inputs=inputs,
            outputs=(output_spec,),
            force=force,
            build=build,
            policy_sha256=effective_policy_sha256,
            capture_input_snapshot=capture_input_snapshot,
            verify_input_snapshot=verify_input_snapshot,
            validate_staged_outputs=validate_staged_outputs,
        )
        verify_runtime_bundle()
        if snapshot is None:
            raise _error("confirmation Oracle input snapshot failed validation")
        runtime_callables["validation.upstream_bundles"](
            snapshot,
            effective_config,
            prompt_variant_validator=runtime_callables["validation.prompt_variant_artifact_bundle"],
            randomization_validator=runtime_callables["validation.randomization_artifact_bundle"],
            generation_validator=runtime_callables["validation.confirmation_generation_bundle"],
            block_builder=runtime_callables["validation.randomization_block_builder"],
            planner=runtime_callables["validation.plan_confirmation_requests"],
            provenance_hasher=runtime_callables["validation.provider_provenance_sha256"],
        )
        payload, _file = runtime_callables["input.read_snapshot"](output, allow_empty=True)
        records = runtime_callables["input.parse_jsonl"](payload, OracleRecord, allow_empty=True)
        verify_runtime_bundle()
        return runtime_callables["relation.validate_confirmation_oracle_coverage"](
            snapshot.assignments, snapshot.executions, snapshot.codes, records
        )


def run_confirmation_oracle_stage(
    config: AppConfig,
    store: RunStore,
    *,
    force: bool,
) -> ConfirmationOracleStageResult:
    """Run the public fail-closed confirmation Oracle stage."""

    runtime_callables: dict[str, object] = {}
    runtime_contract: dict[str, Mapping[str, str]] = {}
    analyzer_runtime: _AnalyzerRuntime | None = None
    failure_code: ErrorCode | None = None
    control: MemoryError | KeyboardInterrupt | SystemExit | None = None
    result: ConfirmationOracleStageResult | None = None
    caught: BaseException | None = None
    try:
        runtime_callables = _confirmation_oracle_runtime_callables()
        runtime_contract = {
            name: _runtime_callable_descriptor(value)
            for name, value in sorted(runtime_callables.items())
        }
        analyzer_runtime = runtime_callables["runtime.analyzer_factory"](config.oracle)
        result = _run_confirmation_oracle_stage(
            config,
            store,
            force=force,
            analyzer_runtime=analyzer_runtime,
            runtime_callables=runtime_callables,
            runtime_contract=runtime_contract,
        )
    except _FATAL as error:
        control = error
    except SecAwareError as error:
        caught = error
        failure_code = error.code
    except Exception as error:
        caught = error
        failure_code = ErrorCode.ANALYZER_FAILED
    finally:
        config = None  # type: ignore[assignment]
        store = None  # type: ignore[assignment]
        analyzer_runtime = None  # type: ignore[assignment]
        runtime_callables = {}
        runtime_contract = {}
        _clear_exception(caught)
        caught = None
    if control is not None:
        control.__traceback__ = None
        raised_control = control
        control = None
        raise raised_control
    if failure_code is not None:
        raise _public_error(failure_code) from None
    if result is None:  # pragma: no cover
        raise _public_error(ErrorCode.ANALYZER_FAILED)
    return result


def validate_committed_confirmation_run(
    config: AppConfig,
    store: RunStore,
) -> ConfirmationOracleStageResult:
    """Validate one terminal M5 commit without executing providers or analyzers."""

    runtime_callables: dict[str, object] = {}
    runtime_contract: dict[str, Mapping[str, str]] = {}
    analyzer_runtime: _AnalyzerRuntime | None = None
    try:
        runtime_callables = _confirmation_oracle_runtime_callables()
        runtime_contract = {
            name: _runtime_callable_descriptor(value)
            for name, value in sorted(runtime_callables.items())
        }
        runtime_callables["input.guard_no_future_artifacts"](
            store,
            traversal=runtime_callables["input.bounded_tree"],
        )
        store.require_committed_output(
            _STAGE,
            (store.path("oracle", _OUTPUT_NAME),),
        )
        analyzer_runtime = runtime_callables["runtime.analyzer_factory"](config.oracle)
        return _run_confirmation_oracle_stage(
            config,
            store,
            force=False,
            analyzer_runtime=analyzer_runtime,
            runtime_callables=runtime_callables,
            runtime_contract=runtime_contract,
            validate_only=True,
        )
    except _FATAL:
        raise
    except SecAwareError:
        raise
    except Exception:
        raise _public_error(ErrorCode.MANIFEST_CONFLICT) from None
    finally:
        config = None  # type: ignore[assignment]
        store = None  # type: ignore[assignment]
        analyzer_runtime = None
        runtime_callables = {}
        runtime_contract = {}


def _confirmation_oracle_runtime_callables() -> dict[str, object]:
    return {
        "adapter.bandit_argv": oracle_aggregator.bandit_argv,
        "adapter.parse_bandit_report": oracle_aggregator.parse_bandit_report,
        "adapter.parse_semgrep_report": oracle_aggregator.parse_semgrep_report,
        "adapter.semgrep_argv": oracle_aggregator.semgrep_argv,
        "aggregate.aggregate_code_analyses": oracle_aggregator._aggregate_code_analyses,
        "aggregate.bind_oracle_analyses": _bind_oracle_analyses,
        "aggregate.dto.analyzer_finding": oracle_aggregator.AnalyzerFindingRecord,
        "aggregate.dto.analyzer_provenance": oracle_aggregator.AnalyzerProvenanceRecord,
        "aggregate.dto.analyzer_report": oracle_aggregator.AnalyzerReport,
        "aggregate.dto.located_finding": oracle_aggregator.LocatedAnalyzerFinding,
        "aggregate.dto.oracle_code_analysis": oracle_aggregator.OracleCodeAnalysis,
        "aggregate.dto.trusted_analyzer_finding": oracle_aggregator._TRUSTED_ANALYZER_FINDING_TYPE,
        "aggregate.dto.trusted_analyzer_provenance": oracle_aggregator._TRUSTED_ANALYZER_PROVENANCE_TYPE,
        "aggregate.dto.trusted_analyzer_report": oracle_aggregator._TRUSTED_ANALYZER_REPORT_TYPE,
        "aggregate.dto.trusted_located_finding": oracle_aggregator._TRUSTED_LOCATED_FINDING_TYPE,
        "aggregate.dto.trusted_oracle_code_analysis": oracle_aggregator._TRUSTED_ORACLE_CODE_ANALYSIS_TYPE,
        "aggregate.oracle_code_input": OracleCodeInput,
        "aggregate.private_analyzer_batch": oracle_aggregator._run_private_analyzer_batch,
        "aggregate.run_oracle_code_batch": oracle_aggregator.run_oracle_code_batch,
        "aggregate.snapshot_code_inputs": oracle_aggregator._snapshot_oracle_code_inputs,
        "aggregate.validate_code_analyses": oracle_aggregator.validate_oracle_code_analyses,
        "aggregate.validate_report_coordinates": oracle_aggregator._validate_report_coordinates,
        "input.bounded_tree": iter_bounded_tree,
        "input.guard_no_future_artifacts": _guard_no_future_artifacts,
        "input.model_shape_is_intact": model_shape_is_intact,
        "input.parse_jsonl": _parse_jsonl,
        "input.parse_manifest": _parse_manifest,
        "input.read_snapshot": _read_snapshot,
        "input.run_store_factory": RunStore,
        "input.strict_json": load_strict_json_bytes,
        "preflight.load_policy_bundle": load_policy_bundle,
        "preflight.run_oracle_preflight": run_oracle_preflight,
        "relation.validate_confirmation_oracle_coverage": validate_confirmation_oracle_coverage,
        "runtime.analyzer_factory": _ANALYZER_RUNTIME_FACTORY,
        "runtime.production_runner": run_analyzer_process,
        "runtime.validator": validate_analyzer_runtime,
        "transaction.execute_jsonl_stage_transaction": execute_jsonl_stage_transaction,
        "transaction.jsonl_output_spec": JsonlOutputSpec,
        "validation.confirmation_generation_bundle": generation_stage.validate_confirmation_generation_bundle,
        "validation.plan_confirmation_requests": generation_stage.plan_confirmation_requests,
        "validation.prompt_variant_artifact_bundle": validate_prompt_variant_artifact_bundle,
        "validation.provider_provenance_sha256": generation_stage.provider_provenance_sha256,
        "validation.randomization_artifact_bundle": randomization_stage.validate_randomization_artifact_bundle,
        "validation.randomization_block_builder": randomization_stage.build_randomization_blocks,
        "validation.upstream_bundles": _validate_upstream_bundles,
    }


def confirmation_oracle_runtime_callable_contract() -> dict[str, dict[str, str]]:
    return {
        name: _runtime_callable_descriptor(value)
        for name, value in sorted(_confirmation_oracle_runtime_callables().items())
    }


def confirmation_oracle_output_policy_contract() -> dict[str, int | str]:
    return {
        "output_name": _OUTPUT_NAME,
        "max_records": _MAX_RECORDS,
        "max_line_bytes": _MAX_LINE_BYTES,
        "max_input_file_bytes": _MAX_INPUT_FILE_BYTES,
        "max_combined_input_bytes": _MAX_COMBINED_INPUT_BYTES,
        "max_total_code_bytes": _MAX_TOTAL_CODE_BYTES,
        "coverage_policy": "generated-exactly-one-terminal-none-v1",
    }


__all__ = [
    "ConfirmationOracleStageResult",
    "confirmation_oracle_output_policy_contract",
    "confirmation_oracle_runtime_callable_contract",
    "run_confirmation_oracle_stage",
    "validate_committed_confirmation_run",
    "validate_confirmation_oracle_coverage",
]

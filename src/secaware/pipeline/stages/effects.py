"""Transactional publication of randomized confirmation ITT artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel

from secaware.analysis.contrasts import materialize_contrasts
from secaware.analysis.cluster_bootstrap import MAX_CLUSTER_TASK_DRAW_MANIFEST_BYTES
from secaware.analysis.itt import (
    MAX_ESTIMATOR_ARTIFACT_RECORDS,
    MAX_ESTIMATOR_DRAW_RECORDS,
    ITTEstimationResult,
    calculate_itt,
)
from secaware.causal.freeze import revalidate_frozen_hypothesis
from secaware.config import AppConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.functional_judge.schema import (
    ProgramFunctionalOutcomeRecord,
    TaskFunctionalContractRecord,
)
from secaware.functional_judge.validation import validate_program_functional_outcomes
from secaware.intervention.attestation import PromptRoleAttestationRecord
from secaware.io.jsonl import read_jsonl
from secaware.io.run_store import RunStore
from secaware.outcomes.assembler import assemble_assignment_outcomes
from secaware.pipeline.artifact import canonical_sha256, sha256_path
from secaware.pipeline.jsonl_stage import JsonlOutputSpec, execute_jsonl_stage_transaction
from secaware.pipeline.manifest import read_stage_manifest
from secaware.pipeline.stages.confirmation_generation import (
    CONFIRMATION_GENERATION_OUTPUTS,
    validate_confirmation_generation_bundle,
)
from secaware.pipeline.stages.confirmation_oracle import (
    validate_confirmation_oracle_coverage,
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
from secaware.schema.causal import FrozenHypothesisRecord
from secaware.schema.experiments import (
    AssignmentExecutionRecord,
    AssignmentRecord,
    ConfirmationProtocolRecord,
    FunctionalOutcomeContractRecord,
    RandomizationManifestRecord,
)
from secaware.schema.generation import GenerationRequestRecord
from secaware.schema.oracle import OracleRecord
from secaware.schema.outcomes import (
    AnalysisFailureRecord,
    AnalysisStage,
    AssignmentOutcomeRecord,
    ContrastSpecRecord,
    EffectBootstrapDrawRecord,
    FunctionalOutcomeRecord,
    ITTEffectRecord,
)
from secaware.schema.prompt_extraction import PromptExtractionProposalRecord
from secaware.schema.records import CanonicalGeneratedCodeRecord, PromptRecord
from secaware.schema.tsg import PromptTSGRecord
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256


_STAGE = "estimate-confirmation-effects"
_PRODUCER_STAGES = (
    "build-confirmation-variants",
    "fci-discovery",
    "randomize-confirmation",
    "generate-confirmation",
    "run-oracle-confirmation",
    "judge-functionality",
    "import-functional-outcomes",
)

EFFECT_STAGE_INPUTS = (
    Path("inputs/prompts.jsonl"),
    Path("tsg/prompt_extraction_proposals.jsonl"),
    Path("tsg/prompt_tsg.jsonl"),
    *(Path("discovery") / name for name, _model in FCI_DISCOVERY_OUTPUTS),
    *(Path("interventions") / name for name, _model in PROMPT_VARIANT_OUTPUTS),
    *(Path("interventions") / name for name, _model in RANDOMIZATION_OUTPUTS),
    *(Path("generation") / name for name, _model in CONFIRMATION_GENERATION_OUTPUTS),
    Path("oracle/confirmation_oracle.jsonl"),
    Path("analysis/functional_outcomes.jsonl"),
    Path("analysis/program_functional_outcomes.jsonl"),
    *(Path(".stages") / f"{stage}.json" for stage in _PRODUCER_STAGES),
)

EFFECT_STAGE_OUTPUTS = (
    (Path("analysis/assignment_outcomes.jsonl"), AssignmentOutcomeRecord),
    (Path("analysis/contrast_specs.jsonl"), ContrastSpecRecord),
    (Path("analysis/effect_bootstrap_draws.jsonl"), EffectBootstrapDrawRecord),
    (Path("analysis/itt_effects.jsonl"), ITTEffectRecord),
    (Path("analysis/effect_failures.jsonl"), AnalysisFailureRecord),
)

_MAX_STANDARD_RECORDS = 100_000
_MAX_STANDARD_LINE_CHARS = 4_000_000
_MAX_STANDARD_TOTAL_CHARS = 256_000_000
# A persisted draw can carry nearly the cluster bootstrap's complete 16 MiB
# task-draw manifest in one replicate. The separate 125k record and 1 GB file
# ceilings keep publication bounded while retaining the required 110k case.
_MAX_EFFECT_DRAW_LINE_CHARS = MAX_CLUSTER_TASK_DRAW_MANIFEST_BYTES + 4_096
_MAX_EFFECT_DRAW_TOTAL_CHARS = 1_000_000_000
_MAX_EFFECT_RECORD_TOTAL_CHARS = 256_000_000
_MAX_FAILURE_RECORD_TOTAL_CHARS = 256_000_000


@dataclass(frozen=True, slots=True)
class _JsonlReadLimits:
    max_records: int
    max_line_chars: int
    max_total_chars: int


_INPUT_READ_LIMITS = _JsonlReadLimits(
    max_records=_MAX_STANDARD_RECORDS,
    max_line_chars=_MAX_STANDARD_LINE_CHARS,
    max_total_chars=_MAX_STANDARD_TOTAL_CHARS,
)


def _effect_output_specs(store: RunStore) -> tuple[JsonlOutputSpec, ...]:
    limits = (
        (_MAX_STANDARD_RECORDS, _MAX_STANDARD_LINE_CHARS, _MAX_STANDARD_TOTAL_CHARS),
        (_MAX_STANDARD_RECORDS, _MAX_STANDARD_LINE_CHARS, _MAX_STANDARD_TOTAL_CHARS),
        (
            MAX_ESTIMATOR_DRAW_RECORDS,
            _MAX_EFFECT_DRAW_LINE_CHARS,
            _MAX_EFFECT_DRAW_TOTAL_CHARS,
        ),
        (
            MAX_ESTIMATOR_ARTIFACT_RECORDS,
            _MAX_STANDARD_LINE_CHARS,
            _MAX_EFFECT_RECORD_TOTAL_CHARS,
        ),
        (
            MAX_ESTIMATOR_ARTIFACT_RECORDS,
            _MAX_STANDARD_LINE_CHARS,
            _MAX_FAILURE_RECORD_TOTAL_CHARS,
        ),
    )
    return tuple(
        JsonlOutputSpec(
            store.root / relative,
            model,
            require_nonempty=index < 2,
            max_records=max_records,
            max_line_chars=max_line_chars,
            max_total_chars=max_total_chars,
        )
        for index, ((relative, model), (max_records, max_line_chars, max_total_chars)) in enumerate(
            zip(EFFECT_STAGE_OUTPUTS, limits, strict=True)
        )
    )


@dataclass(frozen=True, slots=True)
class EffectsStageResult:
    assignment_outcome_count: int
    contrast_count: int
    draw_count: int
    effect_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class _Snapshot:
    input_paths: tuple[Path, ...]
    input_sha256: tuple[str, ...]
    task4_groups: tuple[tuple[BaseModel, ...], ...]
    fci_groups: tuple[tuple[BaseModel, ...], ...]
    randomization_manifest: RandomizationManifestRecord
    assignments: tuple[AssignmentRecord, ...]
    requests: tuple[GenerationRequestRecord, ...]
    executions: tuple[AssignmentExecutionRecord, ...]
    codes: tuple[CanonicalGeneratedCodeRecord, ...]
    oracles: tuple[OracleRecord, ...]
    functional_outcomes: tuple[FunctionalOutcomeRecord, ...]
    task_functional_contracts: tuple[TaskFunctionalContractRecord, ...]
    program_functional_outcomes: tuple[ProgramFunctionalOutcomeRecord, ...]
    program_functional_policy_sha256: str | None
    prompts: tuple[PromptRecord, ...]
    attestations: tuple[PromptRoleAttestationRecord, ...]
    contracts: tuple[FunctionalOutcomeContractRecord, ...]
    source_proposals: tuple[PromptExtractionProposalRecord, ...]
    source_graphs: tuple[PromptTSGRecord, ...]


def _error(message: str = "effect stage artifact validation failed") -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.ANALYSIS_INVALID,
        stage=_STAGE,
        message=message,
        details={},
        retryable=False,
    )


def _read(
    path: Path,
    model: type | None,
    *,
    allow_empty: bool,
    limits: _JsonlReadLimits = _INPUT_READ_LIMITS,
) -> tuple:
    return tuple(
        read_jsonl(
            path,
            model,
            required=True,
            allow_empty=allow_empty,
            max_records=limits.max_records,
            max_line_chars=limits.max_line_chars,
            max_total_chars=limits.max_total_chars,
            stage=_STAGE,
        )
    )


def _read_output(spec: JsonlOutputSpec) -> tuple:
    return tuple(
        read_jsonl(
            spec.path,
            spec.model,
            required=True,
            allow_empty=not spec.require_nonempty,
            max_records=spec.max_records,
            max_line_chars=spec.max_line_chars,
            max_total_chars=spec.max_total_chars,
            stage=_STAGE,
        )
    )


def _producer_paths(store: RunStore) -> dict[str, tuple[Path, ...]]:
    return {
        "build-confirmation-variants": tuple(
            store.path("interventions", name) for name, _model in PROMPT_VARIANT_OUTPUTS
        ),
        "fci-discovery": tuple(
            store.path("discovery", name) for name, _model in FCI_DISCOVERY_OUTPUTS
        ),
        "randomize-confirmation": tuple(
            store.path("interventions", name) for name, _model in RANDOMIZATION_OUTPUTS
        ),
        "generate-confirmation": tuple(
            store.path("generation", name) for name, _model in CONFIRMATION_GENERATION_OUTPUTS
        ),
        "run-oracle-confirmation": (store.path("oracle", "confirmation_oracle.jsonl"),),
        "import-functional-outcomes": (store.path("analysis", "functional_outcomes.jsonl"),),
        "judge-functionality": (
            store.path("analysis", "functional_judge_passes.jsonl"),
            store.path("analysis", "program_functional_outcomes.jsonl"),
        ),
    }


def _validate_fci_public_bundle(groups: tuple[tuple[BaseModel, ...], ...]) -> None:
    if len(groups) != len(FCI_DISCOVERY_OUTPUTS):
        raise _error()
    hypotheses = groups[6]
    if not hypotheses or any(type(item) is not FrozenHypothesisRecord for item in hypotheses):
        raise _error("effect stage frozen hypothesis universe is empty")
    if tuple(revalidate_frozen_hypothesis(item) for item in hypotheses) != hypotheses:
        raise _error()
    for group in groups:
        digests = tuple(canonical_sha256(item.model_dump(mode="json")) for item in group)
        if len(digests) != len(set(digests)):
            raise _error()


def _validate_output_coverage(
    outcomes: tuple[AssignmentOutcomeRecord, ...],
    contrasts: tuple[ContrastSpecRecord, ...],
    result: ITTEstimationResult,
    *,
    bootstrap_samples: int,
) -> None:
    if not outcomes or not contrasts:
        raise _error("effect stage estimand universe is empty")
    semantic_groups = {
        (row.hypothesis_id, row.target_spec_id, row.arm_protocol_id, row.model_id)
        for row in outcomes
    }
    expected_subjects = {
        "effect_coordinate_"
        + canonical_sha256(
            {
                "schema_version": "1.0",
                "effect_coordinate": [
                    *semantic_group,
                    contrast.contrast_id,
                    contrast.outcome_id,
                ],
            }
        )
        for semantic_group in semantic_groups
        for contrast in contrasts
        if contrast.arm_protocol_id == semantic_group[2]
    }
    effect_subjects = {
        "effect_coordinate_"
        + canonical_sha256(
            {
                "schema_version": "1.0",
                "effect_coordinate": [
                    effect.hypothesis_id,
                    effect.target_spec_id,
                    effect.arm_protocol_id,
                    effect.model_id,
                    effect.contrast_id,
                    effect.outcome_id,
                ],
            }
        )
        for effect in result.effects
    }
    failure_subjects = {failure.subject_id for failure in result.failures}
    if (
        not expected_subjects
        or effect_subjects & failure_subjects
        or effect_subjects | failure_subjects != expected_subjects
        or len(effect_subjects) != len(result.effects)
        or any(failure.stage is not AnalysisStage.EFFECTS for failure in result.failures)
        or len({item.effect_id for item in result.effects}) != len(result.effects)
        or len({item.subject_id for item in result.failures}) != len(result.failures)
        or len({item.draw_id for item in result.draws}) != len(result.draws)
    ):
        raise _error()
    draws_by_effect: dict[str, list[EffectBootstrapDrawRecord]] = {}
    for draw in result.draws:
        draws_by_effect.setdefault(draw.effect_id, []).append(draw)
    effect_by_id = {effect.effect_id: effect for effect in result.effects}
    if set(draws_by_effect) - set(effect_by_id):
        raise _error()
    for effect in result.effects:
        draws = draws_by_effect.get(effect.effect_id, [])
        expected = (
            0 if effect.status == "unsupported_missing_functional_outcome" else bootstrap_samples
        )
        if len(draws) != expected:
            raise _error()
        if draws and (
            tuple(item.replicate_index for item in draws) != tuple(range(expected))
            or any(
                item.assignment_universe_sha256 != effect.assignment_universe_sha256
                or item.bootstrap_manifest_sha256 != effect.bootstrap_manifest_sha256
                for item in draws
            )
        ):
            raise _error()


def _assigned_analysis_bundle(
    protocols: tuple[ConfirmationProtocolRecord, ...],
    assignments: tuple[AssignmentRecord, ...],
) -> tuple[tuple[ConfirmationProtocolRecord, ...], tuple[ContrastSpecRecord, ...]]:
    assigned_protocol_ids = {assignment.arm_protocol_id for assignment in assignments}
    selected_protocols = tuple(
        protocol for protocol in protocols if protocol.arm_protocol_id in assigned_protocol_ids
    )
    if (
        not assigned_protocol_ids
        or {protocol.arm_protocol_id for protocol in selected_protocols} != assigned_protocol_ids
    ):
        raise _error("effect stage assignment protocol universe failed validation")
    return selected_protocols, materialize_contrasts(selected_protocols)


def effects_stage(config: AppConfig, store: RunStore, force: bool = False) -> EffectsStageResult:
    """Publish the complete effects bundle while holding every producer lease."""

    if type(config) is not AppConfig or type(store) is not RunStore or store.config != config:
        raise _error("effect stage configuration failed validation")
    producer_paths = _producer_paths(store)
    optional_path = producer_paths["import-functional-outcomes"][0]
    optional_manifest = store.path(".stages", "import-functional-outcomes.json")
    judge_paths = producer_paths["judge-functionality"]
    judge_manifest = store.path(".stages", "judge-functionality.json")
    snapshot: _Snapshot | None = None
    built: tuple[tuple[BaseModel, ...], ...] | None = None

    with store.hold_dependency_stages(_PRODUCER_STAGES):
        try:
            held_sha256: dict[str, dict[str, str]] = {}
            for stage in _PRODUCER_STAGES[:-2]:
                held_sha256[stage] = store.require_committed_output(
                    stage,
                    producer_paths[stage],
                    expected_catalog_sha256=(
                        PROMPT_FEATURE_CATALOG_SHA256
                        if stage == "build-confirmation-variants"
                        else None
                    ),
                )
            optional_state = (optional_path.exists(), optional_manifest.exists())
            if optional_state == (False, False):
                optional_present = False
            elif optional_state == (True, True):
                optional_present = True
                held_sha256["import-functional-outcomes"] = store.require_committed_output(
                    "import-functional-outcomes", (optional_path,)
                )
            else:
                raise _error("functional outcome producer commitment failed validation")
            judge_state = tuple(path.exists() for path in (*judge_paths, judge_manifest))
            if judge_state == (False, False, False):
                judge_present = False
            elif judge_state == (True, True, True):
                judge_present = True
                held_sha256["judge-functionality"] = store.require_committed_output(
                    "judge-functionality", judge_paths
                )
            else:
                raise _error("program functional outcome producer commitment failed validation")
            if config.functional_judge.enabled != judge_present:
                raise _error("program functional outcome producer is required by configuration")

            prompt_path = store.path("inputs", "prompts.jsonl")
            attestation_path = Path(config.data.prompt_attestations_path)
            contract_path = (
                Path(config.data.functional_outcome_contracts_path)
                if config.data.functional_outcome_contracts_path is not None
                else None
            )
            task_contract_path = (
                Path(config.data.task_functional_contracts_path)
                if (judge_present and config.data.task_functional_contracts_path is not None)
                else None
            )
            source_paths = (
                store.path("tsg", "prompt_extraction_proposals.jsonl"),
                store.path("tsg", "prompt_tsg.jsonl"),
            )
            producer_manifests = tuple(
                store.path(".stages", f"{stage}.json") for stage in _PRODUCER_STAGES[:-2]
            )
            input_paths = (
                prompt_path,
                attestation_path,
                *((contract_path,) if contract_path is not None else ()),
                *((task_contract_path,) if task_contract_path is not None else ()),
                *source_paths,
                *(path for stage in _PRODUCER_STAGES[:-2] for path in producer_paths[stage]),
                *producer_manifests,
                *((optional_path, optional_manifest) if optional_present else ()),
                *((*judge_paths, judge_manifest) if judge_present else ()),
            )

            def capture_input_snapshot() -> tuple[str, ...]:
                nonlocal snapshot
                if snapshot is not None:
                    raise _error()
                input_sha256 = tuple(sha256_path(path) for path in input_paths)
                task4_groups = tuple(
                    _read(path, model, allow_empty=index >= 4)
                    for index, (path, (_name, model)) in enumerate(
                        zip(
                            producer_paths["build-confirmation-variants"],
                            PROMPT_VARIANT_OUTPUTS,
                            strict=True,
                        )
                    )
                )
                fci_groups = tuple(
                    _read(path, model, allow_empty=index != 6)
                    for index, (path, (_name, model)) in enumerate(
                        zip(
                            producer_paths["fci-discovery"],
                            FCI_DISCOVERY_OUTPUTS,
                            strict=True,
                        )
                    )
                )
                randomization_groups = tuple(
                    _read(path, model, allow_empty=False)
                    for path, (_name, model) in zip(
                        producer_paths["randomize-confirmation"],
                        RANDOMIZATION_OUTPUTS,
                        strict=True,
                    )
                )
                if len(randomization_groups[0]) != 1:
                    raise _error()
                generation_groups = tuple(
                    _read(path, model, allow_empty=index == 2)
                    for index, (path, (_name, model)) in enumerate(
                        zip(
                            producer_paths["generate-confirmation"],
                            CONFIRMATION_GENERATION_OUTPUTS,
                            strict=True,
                        )
                    )
                )
                prompts = _read(prompt_path, PromptRecord, allow_empty=False)
                attestations = _read(
                    attestation_path, PromptRoleAttestationRecord, allow_empty=False
                )
                contracts = (
                    _read(contract_path, FunctionalOutcomeContractRecord, allow_empty=True)
                    if contract_path is not None
                    else ()
                )
                task_contracts = (
                    _read(task_contract_path, TaskFunctionalContractRecord, allow_empty=False)
                    if task_contract_path is not None
                    else ()
                )
                source_proposals = _read(
                    source_paths[0], PromptExtractionProposalRecord, allow_empty=False
                )
                source_graphs = _read(source_paths[1], PromptTSGRecord, allow_empty=False)
                oracles = _read(
                    producer_paths["run-oracle-confirmation"][0],
                    OracleRecord,
                    allow_empty=True,
                )
                functional = (
                    _read(optional_path, FunctionalOutcomeRecord, allow_empty=True)
                    if optional_present
                    else ()
                )
                program_functional = (
                    _read(judge_paths[1], ProgramFunctionalOutcomeRecord, allow_empty=False)
                    if judge_present
                    else ()
                )
                judge_policy_sha256 = None
                if judge_present:
                    judge_policy_sha256 = read_stage_manifest(judge_manifest).policy_sha256
                    if judge_policy_sha256 is None:
                        raise _error("program functional policy binding failed validation")
                    validate_program_functional_outcomes(
                        randomization_groups[1],
                        task_contracts,
                        program_functional,
                        evaluator_policy_sha256=judge_policy_sha256,
                    )
                _validate_fci_public_bundle(fci_groups)
                validate_prompt_variant_artifact_bundle(
                    config,
                    prompts=prompts,
                    attestations=attestations,
                    contracts=contracts,
                    source_proposals=source_proposals,
                    source_graphs=source_graphs,
                    hypotheses=fci_groups[6],
                    groups=task4_groups,
                )
                validate_randomization_artifact_bundle(
                    randomization_groups[0][0],
                    randomization_groups[1],
                    target_specs=task4_groups[0],
                    target_instances=task4_groups[1],
                    protocols=task4_groups[2],
                    protocol_instances=task4_groups[3],
                    variants=task4_groups[8],
                    exclusions=task4_groups[10],
                    hypotheses=fci_groups[6],
                    confirmation_seeds=tuple(config.generation.confirmation_seeds),
                    global_seed=config.run.random_seed,
                    randomization_config=config.randomization,
                )
                validate_confirmation_generation_bundle(
                    randomization_groups[0][0],
                    randomization_groups[1],
                    task4_groups[8],
                    config,
                    generation_groups[0],
                    generation_groups[1],
                    generation_groups[2],
                )
                validate_confirmation_oracle_coverage(
                    randomization_groups[1],
                    generation_groups[1],
                    generation_groups[2],
                    oracles,
                )
                snapshot = _Snapshot(
                    input_paths=input_paths,
                    input_sha256=input_sha256,
                    task4_groups=task4_groups,
                    fci_groups=fci_groups,
                    randomization_manifest=randomization_groups[0][0],
                    assignments=randomization_groups[1],
                    requests=generation_groups[0],
                    executions=generation_groups[1],
                    codes=generation_groups[2],
                    oracles=oracles,
                    functional_outcomes=functional,
                    task_functional_contracts=task_contracts,
                    program_functional_outcomes=program_functional,
                    program_functional_policy_sha256=judge_policy_sha256,
                    prompts=prompts,
                    attestations=attestations,
                    contracts=contracts,
                    source_proposals=source_proposals,
                    source_graphs=source_graphs,
                )
                return input_sha256

            def verify_input_snapshot() -> None:
                if (
                    snapshot is None
                    or tuple(sha256_path(path) for path in snapshot.input_paths)
                    != snapshot.input_sha256
                ):
                    raise _error("effect stage producers changed during execution")
                for stage, expected in held_sha256.items():
                    current = store.require_committed_output(
                        stage,
                        producer_paths[stage],
                        expected_catalog_sha256=(
                            PROMPT_FEATURE_CATALOG_SHA256
                            if stage == "build-confirmation-variants"
                            else None
                        ),
                    )
                    if current != expected:
                        raise _error("effect stage producers changed during execution")

            def build() -> tuple[tuple[BaseModel, ...], ...]:
                nonlocal built
                if snapshot is None:
                    raise _error()
                frozen_protocols = snapshot.task4_groups[2]
                assignments = snapshot.assignments
                deltas = snapshot.task4_groups[7]
                protocols, contrasts = _assigned_analysis_bundle(
                    frozen_protocols,  # type: ignore[arg-type]
                    assignments,
                )
                contract_ids = {
                    protocol.functional_outcome_contract_id
                    for protocol in protocols
                    if protocol.functional_outcome_contract_id is not None
                }
                contracts = tuple(
                    contract
                    for contract in snapshot.contracts
                    if contract.contract_id in contract_ids
                )
                if {contract.contract_id for contract in contracts} != contract_ids:
                    raise _error("effect stage functional contract universe failed validation")
                if not assignments or not snapshot.fci_groups[6] or not contrasts:
                    raise _error("effect stage estimand universe is empty")
                outcomes = assemble_assignment_outcomes(
                    assignments,
                    snapshot.executions,
                    snapshot.oracles,
                    deltas,
                    protocols=protocols,
                    functional_contracts=contracts,
                    functional_outcomes=snapshot.functional_outcomes,
                    task_functional_contracts=snapshot.task_functional_contracts,
                    program_functional_outcomes=snapshot.program_functional_outcomes,
                    program_functional_policy_sha256=(snapshot.program_functional_policy_sha256),
                )
                result = calculate_itt(
                    outcomes,
                    config.analysis,
                    protocols=protocols,
                    contrasts=contrasts,
                    functional_contracts=contracts,
                    functional_outcomes=snapshot.functional_outcomes,
                )
                _validate_output_coverage(
                    outcomes,
                    contrasts,
                    result,
                    bootstrap_samples=config.analysis.bootstrap_samples,
                )
                built = (
                    outcomes,
                    contrasts,
                    result.draws,
                    result.effects,
                    result.failures,
                )
                return built

            def validate_staged_outputs(
                groups: tuple[tuple[BaseModel | dict[str, object], ...], ...],
            ) -> None:
                if built is None or groups != built:
                    raise _error("effect stage staged output failed validation")
                _validate_output_coverage(
                    groups[0],  # type: ignore[arg-type]
                    groups[1],  # type: ignore[arg-type]
                    ITTEstimationResult(
                        groups[3],  # type: ignore[arg-type]
                        groups[2],  # type: ignore[arg-type]
                        groups[4],  # type: ignore[arg-type]
                    ),
                    bootstrap_samples=config.analysis.bootstrap_samples,
                )

            output_specs = _effect_output_specs(store)
            execute_jsonl_stage_transaction(
                store,
                stage=_STAGE,
                inputs=input_paths,
                outputs=output_specs,
                force=force,
                build=build,
                capture_input_snapshot=capture_input_snapshot,
                verify_input_snapshot=verify_input_snapshot,
                validate_staged_outputs=validate_staged_outputs,
            )
            groups = tuple(_read_output(spec) for spec in output_specs)
            if snapshot is None:
                raise _error()
            _validate_output_coverage(
                groups[0],
                groups[1],
                ITTEstimationResult(groups[3], groups[2], groups[4]),
                bootstrap_samples=config.analysis.bootstrap_samples,
            )
            return EffectsStageResult(*(len(group) for group in groups))
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except SecAwareError:
            raise
        except Exception:
            raise _error() from None


__all__ = [
    "EFFECT_STAGE_INPUTS",
    "EFFECT_STAGE_OUTPUTS",
    "EffectsStageResult",
    "effects_stage",
]
